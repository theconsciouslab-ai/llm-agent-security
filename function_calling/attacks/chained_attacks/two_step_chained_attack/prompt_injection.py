# This attack is two step chain attack:
# prompt_injection -> llm_function_injection

from tqdm import tqdm
from copy import deepcopy
from attacks.base_attack import Attack
from typing import List, Dict
from attacks.chained_attacks.two_step_chained_attack import ScenarioLoader, AttackEvaluator
from __init__ import MessageFormatter
from attacks.chained_attacks.one_step_chained_attack.prompt_injection import PromptInjector

from attacks.chained_attacks.one_step_chained_attack.tool_injection import AzureToolInjector, AWSToolInjector
from attacks.chained_attacks.one_step_chained_attack.llm_function_injection import LLMFunctionInjectionChain
from attacks.chained_attacks.one_step_chained_attack.function_injection import FunctionInjectionChain
from attacks.chained_attacks.one_step_chained_attack.response_injection import ResponseInjectionChain

class PromptInjectionToToolChain(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/two_step/test_prompt_injections/test_chain_prompt_injection_to_api.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages: List[Dict], agent, model_type: str, llm_judge=None) -> Dict:
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing prompt injection -> tool injection chain",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

        for scenario in progress_bar:
            try:
                scenario_messages = deepcopy(messages)
                modified_messages = PromptInjector(scenario_messages).inject_prompt(scenario)
                modified_messages = MessageFormatter.format_messages(
                    llm_provider=model_type,
                    messages=modified_messages,
                )
                injector = self._get_injector(agent, model_type)
                try:
                    injector.inject_tools(scenario.injected_tools)
                    if model_type.lower() == "azure" and hasattr(scenario, 'forced_function'):
                        injector.force_function(scenario.forced_function)
                    
                    injector.activate()
                    response = agent.run_conversation(modified_messages)
                    injector.deactivate()
                    results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)
                finally:
                    injector.deactivate


            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }
    
    def _get_injector(self, agent, model_type: str):
        model_type = model_type.lower()
        if model_type == "azure":
            return AzureToolInjector(agent)
        elif model_type == "aws":
            return AWSToolInjector(agent)
        else:
            raise ValueError(f"Unsupported model type: {model_type}")
    
class PromptInjectionToLLMChain(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/two_step/test_prompt_injections/test_chain_prompt_injection_to_llm_function.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages: List[Dict], agent, model_type: str, llm_judge=None) -> Dict:
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing prompt injection -> LLM Function injection chain",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

        for scenario in progress_bar:
            try:
                scenario_messages = deepcopy(messages)
                modified_messages = PromptInjector(scenario_messages).inject_prompt(scenario)
                modified_messages = MessageFormatter.format_messages(
                    llm_provider=model_type,
                    messages=modified_messages,
                )
                llm_injection_chain = LLMFunctionInjectionChain(
                    name="LLM Injection", 
                    description="Testing llm injection"
                )
                interceptor = llm_injection_chain._get_interceptor(agent, model_type)
                response = interceptor.intercept_conversation(modified_messages, scenario)
                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)

            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }

 
class PromptInjectionToFunctionChain(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/two_step/test_prompt_injections/test_chain_prompt_injection_to_function_injection.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages: List[Dict], agent, model_type: str, llm_judge=None) -> Dict:
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing prompt injection -> Function injection chain",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

        for scenario in progress_bar:
            try:
                scenario_messages = deepcopy(messages)
                modified_messages = PromptInjector(scenario_messages).inject_prompt(scenario)
                modified_messages = MessageFormatter.format_messages(
                    llm_provider=model_type,
                    messages=modified_messages,
                )
                function_injection_chain = FunctionInjectionChain(
                    name="Function Injection", 
                    description="Testing llm injection"
                )
                interceptor = function_injection_chain._get_interceptor(agent, model_type)
                response = interceptor.intercept_conversation(modified_messages, scenario)
                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)

            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }


class PromptInjectionToResponseChain(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/two_step/test_prompt_injections/test_chain_prompt_injection_to_response_injection.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages: List[Dict], agent, model_type: str, llm_judge=None) -> Dict:
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing prompt injection -> Response injection chain",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

        for scenario in progress_bar:
            try:
                scenario_messages = deepcopy(messages)
                modified_messages = PromptInjector(scenario_messages).inject_prompt(scenario)
                modified_messages = MessageFormatter.format_messages(
                    llm_provider=model_type,
                    messages=modified_messages,
                )
                response_injection = ResponseInjectionChain(
                    name="Response Injection", 
                    description="Testing llm injection"
                )
                interceptor = response_injection._get_interceptor(agent, model_type)
                response = interceptor.execute_with_interceptor(modified_messages, scenario)
                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)

            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }
