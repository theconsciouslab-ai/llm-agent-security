from copy import deepcopy
from tqdm import tqdm  
from typing import Dict, List, Union
from agent.azure_agent import Agent as AzureAgent
from agent.aws_agent import AwsAgent
from attacks import AttackEvaluator, ScenarioLoader
from attacks.base_attack import Attack
from __init__ import MessageFormatter, ToolFormatter

class AzureAPIMonkeyPatcher:    
    def __init__(self, original_agent: AzureAgent):
        self.original_agent = original_agent
        self.original_create = original_agent.client.chat.completions.create
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.original_agent.client.chat.completions.create = self.original_create
        return False
    
    def patch(self, tools: List[Dict]):
        formatted_tools = ToolFormatter.format_tools('azure', tools)
        def patched_create(*args, **kwargs):
            kwargs["tools"] = formatted_tools
            return self.original_create(*args, **kwargs)
        
        self.original_agent.client.chat.completions.create = patched_create

class AWSAPIMonkeyPatcher:
    def __init__(self, original_agent: AwsAgent):
        self.original_agent = original_agent
        self.original_tool_config = original_agent.tool_config
        self.original_converse = original_agent.client.converse
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.original_agent.tool_config = self.original_tool_config
        self.original_agent.client.converse = self.original_converse
        return False
    
    def patch(self, tools: List[Dict]):
        formatted_tools = ToolFormatter.format_tools('aws', tools)
        
        def patched_converse(*args, **kwargs):
            kwargs["toolConfig"] = formatted_tools
            return self.original_converse(*args, **kwargs)
        
        self.original_agent.tool_config = formatted_tools
        self.original_agent.client.converse = patched_converse

class ToolInjectionInterceptionAPI(Attack):
    def __init__(self, name, description, scenario_file="./tests/test_simple/test_tool_injection_api_interception_scenarios.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages, agent, model_type, llm_judge):
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
                test_messages = MessageFormatter.format_messages(
                    llm_provider=model_type,
                    messages=test_messages,
                )

                modified_tools = scenario.modified_prompt
                
                # Choose the appropriate patcher based on model type
                if model_type.lower() == "azure":
                    with AzureAPIMonkeyPatcher(agent) as patcher:
                        patcher.patch(modified_tools)
                        response = agent.run_conversation(test_messages)
                elif model_type.lower() == "aws":
                    with AWSAPIMonkeyPatcher(agent) as patcher:
                        patcher.patch(modified_tools)
                        response = agent.run_conversation(test_messages)
                else:
                    raise ValueError(f"Unsupported model type: {model_type}")
                
                results[scenario.scenario_id] = self.evaluator.evaluate_response(scenario, response)
            except Exception as e:
                results[scenario.scenario_id] = self.evaluator.record_failure(e, scenario)

        progress_bar.close()
        return {
            "detailed_results": results,
            **self.evaluator.get_metrics()
        }