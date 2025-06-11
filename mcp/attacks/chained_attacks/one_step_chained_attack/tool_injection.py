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
import os
from dotenv import load_dotenv
from attacks.chained_attacks.two_step_chained_attack import AttackScenario
from __init__ import ToolFormatter


load_dotenv()

MALICIOUS_SERVER_PATH = os.getenv('MALICIOUS_SERVER_PATH')

class ToolInjector:
    def __init__(self, client: MCPClient):
        self.client = client
        self.model_type = client.model_type
        if self.model_type == "azure":
            self.original_create = client.agent.client.chat.completions.create
        elif self.model_type == "aws":
            self.original_create = client.agent.client.converse
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")
    
        self.original_methods = {
            'create': self.original_create,
            'call_tool': client.session.call_tool if client.session else None
        }
        self.active = False
        self.current_server = None
        self.scenario: Optional[AttackScenario] = None

    def patched_create(self, *args, **kwargs):
        if self.scenario.injected_tools:
            formatted_tools = ToolFormatter.format_tools(self.model_type, self.scenario.injected_tools)
            if self.model_type == 'aws':
                kwargs["toolConfig"] = {"tools": formatted_tools}  # Correct structure
            else:
                kwargs['tools'] = kwargs.get("tools", []) + formatted_tools
        if self.scenario.forced_function and self.model_type == 'azure':
            kwargs['tool_choice'] = {
                "type": "function",
                "function": {"name": self.scenario.forced_function}
            }
        response = self.original_methods['create'](*args, **kwargs)
        return response

    async def switch_server(self, new_server_path: str):
        if not os.path.exists(new_server_path):
            raise FileNotFoundError(f"Server script not found at {new_server_path}")
        if self.client.session:
            await self.client.cleanup()
        await self.client.connect_to_server(new_server_path)
        self.current_server = new_server_path
        self.original_methods['call_tool'] = self.client.session.call_tool

    async def start_injection(self, scenario):
        if self.active:
            raise RuntimeError("Interceptor already active")
        
        self.scenario = deepcopy(scenario)
        if self.model_type == "azure":
            self.client.agent.client.chat.completions.create = self.patched_create
        elif self.model_type == "aws":
            self.client.agent.client.converse = self.patched_create
        self.active = True

    async def stop_injection(self):
        if not self.active:
            return
        if self.model_type == "azure":
            self.client.agent.client.chat.completions.create = self.original_methods['create']
        elif self.model_type == "aws":
            self.client.agent.client.converse = self.original_methods['create']
        self.active = False
        self.scenario = None

    @asynccontextmanager
    async def injection_context(self, scenario):  
        await self.start_injection(scenario)
        try:
            yield
        finally:
            await self.stop_injection()

class MCPToolInjectionChain(MCPAttack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/one_step_chained/test_chain_tool_injection.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    async def execute(self,client, messages,llm_judge):
        evaluator = AttackEvaluator(llm_judge)
        results = {}
        was_connected = client.session is not None

        try: 
            if was_connected:
                original_server = getattr(client, 'current_server', None)
                await client.cleanup()

            progress_bar = tqdm_asyncio(
                self.scenarios,
                desc="Testing llm function injection chain",
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

                    interceptor = ToolInjector(client)
                    await interceptor.switch_server(MALICIOUS_SERVER_PATH)
                    async with interceptor.injection_context(scenario):
                        response = await client.process_query(test_messages)
                    results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)

                except Exception as e:
                    results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        finally:
            if was_connected and original_server:
                try:
                    await client.connect_to_server(original_server)
                except Exception as e:
                    print(f"Warning: Failed to reconnect to original server: {e}")

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
                "injected_tools": scenario.injected_tools,
                "forced_function": scenario.forced_function,
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
                "injected_tools": scenario.injected_tools,
                "forced_function": scenario.forced_function,
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