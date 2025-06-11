from tqdm import tqdm
from copy import deepcopy
from typing import Dict, List
from __init__ import MessageFormatter
from attacks.base_attack import Attack
from attacks.chained_attacks.two_step_chained_attack import ScenarioLoader, AttackEvaluator
from attacks.chained_attacks.two_step_chained_attack import BaseInputOutputInterceptor


class LLMToFunctionToResponseChain(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/three_step/test_llm_injections/test_chain_llm_injection_to_function_to_response.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages: List[Dict], agent, model_type: str, llm_judge=None) -> Dict:
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing llm injection -> function injection -> response injection chain",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

        for scenario in progress_bar:
            try:
                scenario_messages = deepcopy(messages)
                scenario_messages.append({
                    "role": "user",
                    "content": scenario.initial_user_prompt
                })
                modified_messages = MessageFormatter.format_messages(
                    llm_provider=model_type,
                    messages=scenario_messages,
                )
                llm_function_response_injector = BaseInputOutputInterceptor._get_interceptor(agent, model_type)
                response = llm_function_response_injector.intercept_conversation(modified_messages, scenario)
                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)

            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)


        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }