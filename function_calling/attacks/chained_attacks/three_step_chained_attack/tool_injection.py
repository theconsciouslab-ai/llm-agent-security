from tqdm import tqdm
from copy import deepcopy
from typing import Dict, List
from attacks.base_attack import Attack
from __init__ import MessageFormatter
from attacks.chained_attacks.two_step_chained_attack import ScenarioLoader, AttackEvaluator
from attacks.chained_attacks.two_step_chained_attack import BaseInputOutputInterceptor
from attacks.chained_attacks.one_step_chained_attack.tool_injection import ToolInjectionChain
from attacks.chained_attacks.three_step_chained_attack import LLMResponseInjectionInterceptor, FunctionResponseInjectionInterceptor

class ToolToLLMToFunctionChain(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/three_step/test_tool_injections/test_chain_tool_injection_to_llm_function.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages: List[Dict], agent, model_type: str, llm_judge=None) -> Dict:
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing tool injection -> llm injection -> function injection chain",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

        for scenario in progress_bar:
            response = None  
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
                tool_injection = ToolInjectionChain(
                    name="Tool Injection", 
                    description="Testing tool injection"
                )
                

                
                tool_injector = tool_injection._get_injector(agent, model_type)
                llm_function_injector = BaseInputOutputInterceptor._get_interceptor(agent, model_type)

                tool_injector.activate()
                tool_injector.inject_tools(scenario.injected_tools)
                if model_type.lower() == "azure" and hasattr(scenario, 'forced_function'):
                    tool_injector.force_function(scenario.forced_function)
                response = llm_function_injector.intercept_conversation(modified_messages, scenario)
                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)
                
            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)
            finally:
                tool_injector.deactivate()


        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }


class ToolToLLMToResponseChain(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/three_step/test_tool_injections/test_chain_tool_injection_to_llm_to_response.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages: List[Dict], agent, model_type: str, llm_judge=None) -> Dict:
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing tool injection -> llm injection -> response injection chain",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

        for scenario in progress_bar:
            response = None  
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
                tool_injection = ToolInjectionChain(
                    name="Tool Injection", 
                    description="Testing tool injection"
                )
                
                tool_injector = tool_injection._get_injector(agent, model_type)
                llm_response_injector = BaseInputOutputInterceptor._get_interceptor(agent, model_type)

                tool_injector.activate()
                tool_injector.inject_tools(scenario.injected_tools)
                if model_type.lower() == "azure" and hasattr(scenario, 'forced_function'):
                    tool_injector.force_function(scenario.forced_function)
                response = llm_response_injector.intercept_conversation(modified_messages, scenario)
                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)
                
            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)
            finally:
                tool_injector.deactivate()

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }


class ToolToFunctionToResponseChain(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/three_step/test_tool_injections/test_chain_tool_injection_to_function_to_response.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages: List[Dict], agent, model_type: str, llm_judge=None) -> Dict:
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing tool injection -> function injection -> response injection chain",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

        for scenario in progress_bar:
            response = None  
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
                tool_injection = ToolInjectionChain(
                    name="Tool Injection", 
                    description="Testing tool injection"
                )
                
                tool_injector = tool_injection._get_injector(agent, model_type)
                function_response_injector = BaseInputOutputInterceptor._get_interceptor(agent, model_type)

                tool_injector.activate()
                tool_injector.inject_tools(scenario.injected_tools)
                if model_type.lower() == "azure" and hasattr(scenario, 'forced_function'):
                    tool_injector.force_function(scenario.forced_function)
                response = function_response_injector.intercept_conversation(modified_messages, scenario)
                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)
                
            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)
            finally:
                tool_injector.deactivate()

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }
