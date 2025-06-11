from tqdm import tqdm
from copy import deepcopy
from attacks.base_attack import Attack
from typing import List, Dict
from __init__ import MessageFormatter
from attacks.chained_attacks.two_step_chained_attack import ScenarioLoader, AttackEvaluator
from attacks.chained_attacks.one_step_chained_attack.tool_injection import ToolInjectionChain
from attacks.chained_attacks.one_step_chained_attack.llm_function_injection import LLMFunctionInjectionChain
from attacks.chained_attacks.one_step_chained_attack.function_injection import FunctionInjectionChain
from attacks.chained_attacks.one_step_chained_attack.response_injection import ResponseInjectionChain

class ToolInjectionToLLMChain(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/two_step/test_tool_injections/test_chain_tool_injection_to_llm_injection.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages: List[Dict], agent, model_type: str, llm_judge=None) -> Dict:
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing tool injection -> llm injection chain",
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

                scenario_messages = MessageFormatter.format_messages(
                    llm_provider=model_type,
                    messages=scenario_messages,
                )
                tool_injection = ToolInjectionChain(
                    name="Tool Injection", 
                    description="Testing tool injection"
                )
                llm_injection = LLMFunctionInjectionChain(
                    name="llm Injection", 
                    description="Testing llm injection"
                )

                tool_injector = tool_injection._get_injector(agent, model_type)
                llm_injector = llm_injection._get_interceptor(agent, model_type)
                try:
                    tool_injector.inject_tools(scenario.injected_tools)
                    if model_type.lower() == "azure" and hasattr(scenario, 'forced_function'):
                        tool_injector.force_function(scenario.forced_function)
                    
                    tool_injector.activate()
                    response = llm_injector.intercept_conversation(scenario_messages, scenario)
                finally:
                    tool_injector.deactivate()
                    results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)
            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }


class ToolInjectionToFunctionChain(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/two_step/test_tool_injections/test_chain_tool_injection_to_function_injection.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages: List[Dict], agent, model_type: str, llm_judge=None) -> Dict:
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing tool injection -> function injection chain",
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

                scenario_messages = MessageFormatter.format_messages(
                    llm_provider=model_type,
                    messages=scenario_messages,
                )
                
                tool_injection = ToolInjectionChain(
                    name="Tool Injection", 
                    description="Testing tool injection"
                )
                function_injection = FunctionInjectionChain(
                    name="Function Injection", 
                    description="Testing function injection"
                )

                tool_injector = tool_injection._get_injector(agent, model_type)
                function_injector = function_injection._get_interceptor(agent, model_type)
                
                tool_injector.inject_tools(scenario.injected_tools)
                if model_type.lower() == "azure" and hasattr(scenario, 'forced_function'):
                    tool_injector.force_function(scenario.forced_function)
                
                tool_injector.activate()
                response = function_injector.intercept_conversation(scenario_messages, scenario)
                tool_injector.deactivate()  
                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)

            except Exception as e:
                tool_injector.deactivate()  
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }


class ToolInjectionToResponseChain(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/two_step/test_tool_injections/test_chain_tool_injection_to_response_injection.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages: List[Dict], agent, model_type: str, llm_judge=None) -> Dict:
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing tool injection -> response injection chain",
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

                scenario_messages = MessageFormatter.format_messages(
                    llm_provider=model_type,
                    messages=scenario_messages,
                )
                tool_injection = ToolInjectionChain(
                    name="Tool Injection", 
                    description="Testing tool injection"
                )
                response_injection = ResponseInjectionChain(
                    name="Response Injection", 
                    description="Testing response injection"
                )

                tool_injector = tool_injection._get_injector(agent, model_type)
                response_injector = response_injection._get_interceptor(agent, model_type)
                try:
                    tool_injector.inject_tools(scenario.injected_tools)
                    if model_type.lower() == "azure" and hasattr(scenario, 'forced_function'):
                        tool_injector.force_function(scenario.forced_function)
                    
                    tool_injector.activate()
                    response = response_injector.execute_with_interceptor(scenario_messages, scenario)
                finally:
                    tool_injector.deactivate()
                    results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)
            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }
