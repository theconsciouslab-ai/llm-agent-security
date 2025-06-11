from attacks import ScenarioLoader, AttackEvaluator
from typing import Dict, List
from copy import deepcopy
from tqdm import tqdm
from attacks.base_attack import Attack
from __init__ import MessageFormatter


class MessageBuilder:
    @staticmethod
    def build_attack_messages(base_messages: List[Dict], 
                             initial_prompt: str, 
                             modified_prompt: str) -> List[Dict]:
        messages = deepcopy(base_messages)
        messages.extend([
            {"role": "user", "content": initial_prompt},
            {"role": "user", "content": modified_prompt}
        ])
        return messages
        
class UserInputModification(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_simple/test_user_prompt_scenarios.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages, agent, model_type, llm_judge):

        self.evaluator = AttackEvaluator(llm_judge)
        results = {}
        
        with tqdm(
            self.scenarios,
            desc="Testing user prompt scenarios",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        ) as progress_bar:
            
            for scenario in progress_bar:
                try:
                    # Build attack messages
                    test_messages = MessageBuilder.build_attack_messages(messages, scenario.initial_user_prompt,scenario.modified_prompt)

                    test_messages = MessageFormatter.format_messages(
                        llm_provider=model_type,
                        messages= test_messages,
                    )
                    
                    # Execute attack
                    response = agent.run_conversation(test_messages)
                    results[scenario.scenario_id] = self.evaluator.evaluate_response(scenario, response)
                    
                except Exception as e:
                    results[scenario.scenario_id] = self.evaluator.record_failure(e, scenario)
                
                

        progress_bar.close()
        return {
            "detailed_results": results,
            **self.evaluator.get_metrics()
        }