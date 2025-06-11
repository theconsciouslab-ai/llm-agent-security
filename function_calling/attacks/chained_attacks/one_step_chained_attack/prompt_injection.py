# This attack is two step chain attack:
# prompt_injection : system and user prompt injection

import json
from tqdm import tqdm
from typing import Dict, List
from dataclasses import dataclass
from metrics.attack_success_rate import ASR
from metrics.refusal_rate import RefusalRate
from attacks.base_attack import Attack
from attacks.simple_attacks.prompt_injections.system_prompt_modification import SystemPromptModifier
from attacks.simple_attacks.prompt_injections.user_prompt_modification import MessageBuilder
from attacks.chained_attacks.two_step_chained_attack import AttackScenario
from __init__ import MessageFormatter



class PromptInjector:
    def __init__(self, original_messages: List[Dict]):
        self.original_messages = original_messages.copy()  

    def inject_prompt(self, scenario) -> List[Dict]:
        # System prompt modification
        if hasattr(scenario, 'system_prompt_modification') and scenario.system_prompt_modification:
            modified_messages = SystemPromptModifier.modify_system_prompt(
                self.original_messages,
                scenario.system_prompt_modification
            )
        # User prompt modification
        if hasattr(scenario, 'user_prompt_modification') and scenario.user_prompt_modification:
            modified_messages = MessageBuilder.build_attack_messages(
                modified_messages,
                scenario.initial_user_prompt,
                scenario.user_prompt_modification
            )    
        return modified_messages


class PromptInjectionChain(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/one_step/test_chain_prompt_injection.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages, agent, model_type, llm_judge):
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing prompt injection chain",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

        for scenario in progress_bar:
            try:
                modified_messages = PromptInjector(messages).inject_prompt(scenario)
                modified_messages = MessageFormatter.format_messages(
                        llm_provider=model_type,
                        messages= modified_messages,
                )
                response = agent.run_conversation(modified_messages)
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
            "scenario_prompt": { 
                "system_prompt_modification": scenario.system_prompt_modification,
                "user_prompt_modification":scenario.user_prompt_modification,
                },
            "attack_success": self.asr.detect_tampering(
                scenario.expected_result, 
                actual_result
            ),
            "refusal_success": self.refusal_rate.detect_refusal(
                scenario.user_prompt_modification,
                actual_result["llm_response"]
            ),
            "actual_result": actual_result,
            "expected_result": scenario.expected_result
        }
    
    def record_failure(self, error: Exception, scenario: AttackScenario) -> Dict:
        failure_record = {
            "status": "FAILED",
            "scenario_prompt": { 
                "system_prompt_modification": scenario.system_prompt_modification,
                "user_prompt_modification":scenario.user_prompt_modification,
            },
            "error": str(error),
            "error_type": type(error).__name__
        }
        self.asr.get_attack_logs().append({
            "expected": scenario.expected_result,
            "actual": failure_record,
            "success": False
        })
        return failure_record
    
    def get_metrics(self) -> Dict:
        return {
            "success_rate": self.asr.calculate_attack_success_rate(),
            "refusal_rate": self.refusal_rate.calculate_refusal_rate()
        }
