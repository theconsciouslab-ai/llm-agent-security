from tqdm import tqdm
from copy import deepcopy
from attacks.base_attack import Attack
from typing import List, Dict
from __init__ import MessageFormatter
from attacks.chained_attacks.two_step_chained_attack import ScenarioLoader, AttackEvaluator
from attacks.chained_attacks.one_step_chained_attack.prompt_injection import PromptInjector
from attacks.chained_attacks.one_step_chained_attack.tool_injection import ToolInjectionChain
from attacks.chained_attacks.two_step_chained_attack import BaseInputOutputInterceptor

class PromptToToolToLLMToFunctionToResponseChain(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/five_step/test_chain_prompt_injection_tool_to_llm_to_function_to_response.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages: List[Dict], agent, model_type: str, llm_judge=None) -> Dict:
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing prompt injection -> tool injection -> llm injection -> function injection -> response injection chain",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

        for scenario in progress_bar:
            response = None  
            try:
                scenario_messages = deepcopy(messages)
                tool_injection = ToolInjectionChain(
                    name="Tool Injection", 
                    description="Testing tool injection"
                )
                modified_messages = PromptInjector(scenario_messages).inject_prompt(scenario)
                modified_messages = MessageFormatter.format_messages(
                    llm_provider=model_type,
                    messages=modified_messages,
                )

                
                tool_injector = tool_injection._get_injector(agent, model_type)
                llm_function_response_injector = BaseInputOutputInterceptor._get_interceptor(agent, model_type)

                tool_injector.activate()
                tool_injector.inject_tools(scenario.injected_tools)
                if model_type.lower() == "azure" and hasattr(scenario, 'forced_function'):
                    tool_injector.force_function(scenario.forced_function)
                response = llm_function_response_injector.intercept_conversation(modified_messages, scenario)
                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)
                
            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)
            finally:
                tool_injector.deactivate()

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }
