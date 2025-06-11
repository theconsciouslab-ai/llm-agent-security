from attacks import ScenarioLoader, AttackEvaluator
from typing import Dict, List
from copy import deepcopy
from tqdm import tqdm
from attacks.base_attack import Attack
from __init__ import MessageFormatter
          
class SystemPromptModifier:
    @staticmethod
    def modify_system_prompt(messages: List[Dict], new_prompt: str) -> List[Dict]:
        modified_messages = deepcopy(messages)
        for msg in modified_messages:
            if msg["role"] == "system":
                msg["content"] = new_prompt
        return modified_messages
   
class SystemPromptModification(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_simple/test_system_prompt_scenarios.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages, agent, model_type, llm_judge):
        self.evaluator = AttackEvaluator(llm_judge)
        results = {}
        
        progress_bar = tqdm(
            self.scenarios,
            desc="Testing scenarios",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

        for scenario in progress_bar:
            try:
                # Prepare modified messages
                test_messages = SystemPromptModifier.modify_system_prompt(
                    messages, scenario.modified_prompt
                )
                test_messages.append({
                    "role": "user",
                    "content": scenario.initial_user_prompt
                })

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