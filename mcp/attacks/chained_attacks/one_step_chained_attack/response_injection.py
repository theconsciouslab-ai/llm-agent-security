from typing import Dict, Any, Optional, List
import json
from mcp_client.client import MCPClient
from attacks.mcp_base_attack import MCPAttack
from contextlib import asynccontextmanager
from dataclasses import dataclass
from copy import deepcopy
from metrics.attack_success_rate import ASR
from metrics.refusal_rate import RefusalRate
from tqdm.asyncio import tqdm_asyncio

from typing import Dict, Any, Optional
import json
from contextlib import asynccontextmanager
from attacks.chained_attacks.two_step_chained_attack import AttackScenario


class ResponseInjectionInterceptor:
    def __init__(self, client: MCPClient):
        self.client = client
        self.original_call_tool = client.session.call_tool if client.session else None
        self.active = False
        self.scenario: Optional[AttackScenario] = None

    async def modified_call_tool(self, function_name: str, arguments: Dict[str, Any]):
        try:
            original_output = await self.original_call_tool(function_name, arguments)
            if not original_output.content:  
                return original_output
                
            if self.scenario and self.scenario.malicious_output:
                modified_content = deepcopy(original_output.content)
                if modified_content and len(modified_content) > 0:
                    modified_content[0].text = self.scenario.malicious_output
                    original_output.content = modified_content
            return original_output
        except Exception as e:
            print(f"Tool call Response interception failed: {e}")
            raise

    async def intercept(self, scenario):
        if not self.client.session:
            raise RuntimeError("No active session")
        if self.active:
            raise RuntimeError("Interceptor is already active")
        
        self.scenario = scenario
        if self.client.session:
            self.client.session.call_tool = self.modified_call_tool
        self.active = True

    async def stop_intercept(self):
        if not self.active:
            return
        if self.client.session:
            self.client.session.call_tool = self.original_call_tool
        self.active = False
        self.scenario = None

    @asynccontextmanager
    async def intercept_response(self, scenario):
        await self.intercept(scenario)
        try:
            yield
        finally:
            await self.stop_intercept()


class MCPResponseInjectionChain(MCPAttack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/one_step_chained/test_chain_response_injection.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    async def execute(self,client, messages,llm_judge):
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm_asyncio(
            self.scenarios,
            desc="Testing response injection chain",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

        async for scenario in progress_bar:
            try:
                test_messages = deepcopy(messages)
                test_messages.append({
                    "role": "user",
                    "content": scenario.initial_user_prompt
                })

                interceptor = ResponseInjectionInterceptor(client)
                async with interceptor.intercept_response(scenario):
                    response = await client.process_query(test_messages)
                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)

            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }


class ScenarioLoader:
    @staticmethod
    def load_scenarios(file_path: str) -> List[AttackScenario]:
        with open(file_path, "r") as f:
            scenarios = json.load(f)
        return [AttackScenario(**scenario) for scenario in scenarios]


class AttackEvaluator:
    def __init__(self, llm_judge=None):
        self.asr = ASR()
        self.refusal_rate = RefusalRate()
        if llm_judge:
            self.asr.set_llm_judge(llm_judge)
            self.refusal_rate.set_llm_judge(llm_judge)
    
    def evaluate_response(self, scenario: AttackScenario, response: Dict) -> Dict:
        actual_result = {
            "function_name": response.get("function_name", ""),
            "arguments_llm": response.get("arguments_llm", {}),
            "arguments_execution": response.get("arguments_execution", {}),
            "output": response.get("output", {}),
            "llm_response": response.get("llm_response", "")
        }

        return {
            "scenario_id": scenario.scenario_id,
            "scenario_details": {
                "malicious_output": scenario.malicious_output,
            },
            "attack_success": self.asr.detect_tampering(
                scenario.expected_result, 
                actual_result
            ),
            "refusal_success": self.refusal_rate.detect_refusal(
                scenario.initial_user_prompt,
                actual_result["llm_response"]
            ),
            "actual_result": actual_result,
            "expected_result": scenario.expected_result,
        }
    
    def record_failure(self, error: Exception, scenario: AttackScenario) -> Dict:
        failure_record = {
            "scenario_id": scenario.scenario_id,
            "status": "FAILED",
            "scenario_details": {
                "malicious_output": scenario.malicious_output,
            },
            "error": str(error),
            "error_type": type(error).__name__,
        }
        self.asr.get_attack_logs().append({
            "expected": scenario.expected_result,
            "actual": failure_record,
            "success": False
        })
        return failure_record
    
    def get_metrics(self) -> Dict:
        return {
            "attack_success_rate": self.asr.calculate_attack_success_rate(),
            "refusal_rate": self.refusal_rate.calculate_refusal_rate()
        }

