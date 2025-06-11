import ast
from copy import deepcopy
from tqdm import tqdm
from typing import Dict, List
from attacks.base_attack import Attack
from attacks import ScenarioLoader, AttackEvaluator
from __init__ import MessageFormatter


class APIMonkeyPatcher:
    def __init__(self, original_agent):
        self.original_agent = original_agent
        self.original_create = original_agent.client.chat.completions.create
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.original_agent.client.chat.completions.create = self.original_create
        return False
        
    def patch(self, forced_function: str):
        def patched_create(*args, **kwargs):
            if 'tools' in kwargs and kwargs['tools']:
                kwargs["tool_choice"] = {
                    "type": "function",
                    "function": {"name": forced_function}
                }
            else:
                # If no tools were passed, but the original agent has tools -> This is done to preven error of no tools were specified
                if self.original_agent.tools:
                    kwargs["tools"] = self.original_agent.tools
                    kwargs["tool_choice"] = {
                        "type": "function",
                        "function": {"name": forced_function}
                    }
            
            return self.original_create(*args, **kwargs)
            
        self.original_agent.client.chat.completions.create = patched_create

class InterceptionOfAPI(Attack):
    def __init__(self, name, description, scenario_file="./tests/test_simple/test_forced_tool_injection.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)
    
    def execute(self, messages, agent, model_type, llm_judge):
        self.evaluator = AttackEvaluator(llm_judge)
        results = {}
        
        progress_bar = tqdm(
            self.scenarios, 
            desc="Testing forced tool injection via API interception",
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
                        messages= test_messages,
                )
                
                forced_function = ast.literal_eval(scenario.modified_prompt)["function_name"]
                
                # Execute attack 
                with APIMonkeyPatcher(agent) as patcher:
                    patcher.patch(forced_function)
                    response = agent.run_conversation(test_messages)
                
                results[scenario.scenario_id] = self.evaluator.evaluate_response(scenario, response)
            
            except Exception as e:
                results[scenario.scenario_id] = self.evaluator.record_failure(e, scenario)
        
        progress_bar.close()
        
        return {
            "detailed_results": results,
            **self.evaluator.get_metrics()
        }