import json
from copy import deepcopy
from tqdm import tqdm
from attacks.mcp_base_attack import MCPAttack
from mcp_client.client import MCPClient
from attacks import AttackEvaluator, ScenarioLoader
from typing import Dict, List
from __init__ import ToolFormatter


# This technique uses monkey patching to modify the tools argument passed in the API
class APIMonkeyPatcher:    
    def __init__(self, originial_client: MCPClient):
        self.originial_client = originial_client
        self.model_type = originial_client.model_type
        if self.model_type == "azure":
            self.original_create = originial_client.agent.client.chat.completions.create
        elif self.model_type == "aws":
            self.original_create = originial_client.agent.client.converse
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.model_type == "azure":
            self.originial_client.agent.client.chat.completions.create = self.original_create
        elif self.model_type == "aws":
            self.originial_client.agent.client.converse = self.original_create
        return False
    
    def patch(self, tools: List[Dict]):
        def patched_create(*args, **kwargs):
            formatted_tools = ToolFormatter.format_tools(self.model_type, tools)
            if self.model_type == 'aws':
                kwargs["toolConfig"] = {"tools": formatted_tools}
            else:
                kwargs["tools"] = formatted_tools
            return self.original_create(*args, **kwargs)
        
        if self.model_type == 'aws':
            self.originial_client.agent.client.converse = patched_create
        else:
            self.originial_client.agent.client.chat.completions.create = patched_create


class MCPToolsMITM(MCPAttack):
    def __init__(self, name, description, scenario_file="./tests/test_simple/test_tool_injection_api_interception_scenarios.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    async def execute(self, client, messages, llm_judge):
        results = {}
        self.evaluator = AttackEvaluator(llm_judge)

        progress_bar = tqdm(
            self.scenarios, 
            desc="Testing tool injection via API interception", 
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

        for scenario in progress_bar:
            try:
                test_messages = deepcopy(messages)
                test_messages.append({
                    "role": "user",
                    "content": scenario.initial_user_prompt
                })

                modified_tools = scenario.modified_prompt
                
                with APIMonkeyPatcher(client) as patcher:
                    patcher.patch(modified_tools)
                    response = await client.process_query(test_messages)
                
                results[scenario.scenario_id] = self.evaluator.evaluate_response(scenario, response)
            except Exception as e:
                results[scenario.scenario_id] = self.evaluator.record_failure(e, scenario)

        progress_bar.close()
        return {
            "detailed_results": results,
            **self.evaluator.get_metrics()
        }