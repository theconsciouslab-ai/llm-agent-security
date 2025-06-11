import json
from tqdm import tqdm
from copy import deepcopy
from typing import Dict, Any, List
from attacks import ScenarioLoader, AttackEvaluator
from attacks.mcp_base_attack import MCPAttack
from mcp_client.client import MCPClient

class FunctionArgumentInjector:
    def __init__(self, original_client: MCPClient):
        self.original_client = original_client
        self.original_call_tool = original_client.session.call_tool
        self.modified_args = None
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.original_client.session.call_tool = self.original_call_tool
        return False  
        
    def patch(self, args_modifier_function):
        async def patched_call_tool(function_name, function_args):
            modified_args = args_modifier_function(function_name, function_args)
            return await self.original_call_tool(function_name, modified_args)
                
        self.original_client.session.call_tool = patched_call_tool
    
    async def inject_arguments(self, client, messages, injected_args):
        # JSON injection
        def modify_args(function_name, function_args):
            merged_args = {**function_args, **injected_args}
            self.modified_args = merged_args
            return merged_args

        self.patch(modify_args)  
        response = await client.process_query(messages)
        return response

class ArgumentInjectionLoader(ScenarioLoader):
    @staticmethod
    def filter_argument_scenarios(scenarios: List[ScenarioLoader]) -> List[ScenarioLoader]:
        filtered = []
        for idx, scenario in enumerate(scenarios, 1):
            try:
                data = json.loads(scenario.modified_prompt)
                if not isinstance(data, dict) or "function_name" in data:
                    continue
                filtered_scenario = deepcopy(scenario)
                filtered_scenario.scenario_id = str(idx)
                filtered.append(filtered_scenario)
            except json.JSONDecodeError:
                continue
        return filtered

class MCPJsonInjectionFunctionArgument(MCPAttack):
    def __init__(self, name, description, scenario_file="./tests/test_simple/test_json_injection_scenarios.json"):
        super().__init__(name, description)
        self.scenarios = ArgumentInjectionLoader.filter_argument_scenarios(
            ScenarioLoader.load_scenarios(scenario_file)
        )
    
    async def execute(self, client, messages, llm_judge):
        evaluator = AttackEvaluator(llm_judge)
        results = {}
        
        with tqdm(
            self.scenarios,
            desc="Testing function argument corruption via JSON injection",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        ) as progress_bar:
            
            for scenario in progress_bar:
                try:
                    test_messages = deepcopy(messages)
                    test_messages.append({
                        "role": "user",
                        "content": scenario.initial_user_prompt
                    })
                    
                    
                    # Create the injector
                    injector = FunctionArgumentInjector(client)
                    
                    # Execute attack with injected arguments from the scenario
                    injected_args = json.loads(scenario.modified_prompt)
                    response = await injector.inject_arguments(client, test_messages, injected_args)
                    
                    results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)
                    
                except Exception as e:
                    results[scenario.scenario_id] = evaluator.record_failure(e, scenario)
        
        progress_bar.close()
        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }