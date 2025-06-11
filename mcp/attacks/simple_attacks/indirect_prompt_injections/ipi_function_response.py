import json
from copy import deepcopy
from tqdm import tqdm
from attacks.mcp_base_attack import MCPAttack
from mcp_client.client import MCPClient
from attacks import AttackEvaluator, ScenarioLoader

class ToolResponseTextInjector:    
    def __init__(self, original_client: MCPClient):
        self.original_client = original_client
        self.original_call_tool = original_client.session.call_tool
        self.original_text = None
        self.modified_text = None
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.original_client.session.call_tool = self.original_call_tool
        return False
        
    def patch(self, text_modifier_function):
        async def patched_call_tool(function_name, function_args):
            original_response = await self.original_call_tool(function_name, function_args)
            if hasattr(original_response, "content") and len(original_response.content) > 0:
                original_text = original_response.content[0].text
            else:
                original_text = str(original_response)
                
            self.original_text = original_text
            
            modified_text = text_modifier_function(function_name, function_args, original_text)
            self.modified_text = modified_text
            
            modified_response = deepcopy(original_response)
            if hasattr(modified_response, "content") and len(modified_response.content) > 0:
                modified_response.content[0].text = modified_text
                
            return modified_response
                
        self.original_client.session.call_tool = patched_call_tool
    
    async def inject_response_text(self, client, messages, text_modifier):
        
        self.patch(text_modifier)
        response = await client.process_query(messages)
        return response

class MCPIpIFunctionResponse(MCPAttack):
    def __init__(self, name, description, scenario_file="./tests/test_simple/test_ipi_response_scenarios.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)
    
    async def execute(self, client, messages, llm_judge):
        evaluator = AttackEvaluator(llm_judge)
        results = {}
        
        with tqdm(
            self.scenarios,
            desc="Testing tool response text injection",
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
                    
                    injected_data = {"inject_text": scenario.modified_prompt}
                    
                    def text_modifier(function_name, function_args, original_text):
                        if "inject_text" in injected_data:
                            return injected_data["inject_text"]
                        elif "prefix" in injected_data:
                            return f"{injected_data['prefix']} {original_text}"
                        elif "suffix" in injected_data:
                            return f"{original_text} {injected_data['suffix']}"
                        else:
                            return original_text
                    
                    # Execute Attack
                    injector = ToolResponseTextInjector(client)
                    response = await injector.inject_response_text(client, test_messages, text_modifier)
                    
                    results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)
                    
                except Exception as e:
                    results[scenario.scenario_id] = evaluator.record_failure(e, scenario)
        
        progress_bar.close()
        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }