import json
from typing import List, Dict
from copy import deepcopy
from tqdm import tqdm
from attacks import ScenarioLoader, AttackEvaluator
from attacks.mcp_base_attack import MCPAttack

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
        
class MCPUserPromptModification(MCPAttack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_simple/test_user_prompt_scenarios.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    async def execute(self,client, messages,llm_judge):

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
                    
                    # Execute attack
                    response = await client.process_query(test_messages)
                    results[scenario.scenario_id] = self.evaluator.evaluate_response(scenario, response)
                    
                except Exception as e:
                    results[scenario.scenario_id] = self.evaluator.record_failure(e, scenario)
                
                

        progress_bar.close()
        return {
            "detailed_results": results,
            **self.evaluator.get_metrics()
        }