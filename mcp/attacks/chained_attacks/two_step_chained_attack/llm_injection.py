from tqdm.asyncio import tqdm_asyncio
from copy import deepcopy
from attacks.mcp_base_attack import MCPAttack
from attacks.chained_attacks.two_step_chained_attack import ScenarioLoader, AttackEvaluator
from attacks.chained_attacks.one_step_chained_attack.llm_injection import LLMModifier
from attacks.chained_attacks.one_step_chained_attack.function_injection import FunctionInjectionInterceptor
from attacks.chained_attacks.one_step_chained_attack.response_injection import ResponseInjectionInterceptor


class MCPLLMInjectionToFunctionChain(MCPAttack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/two_step_chained/test_llm_injections/test_chain_llm_injection_to_function_injection.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    async def execute(self,client, messages,llm_judge):
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm_asyncio(
            self.scenarios,
            desc="Testing llm injection -> function injection chain",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

        async for scenario in progress_bar:
            try:
                test_messages = deepcopy(messages)
                test_messages.append({
                    "role": "user",
                    "content": scenario.initial_user_prompt
                })

                llm_interceptor = LLMModifier(client)
                fn_interceptor = FunctionInjectionInterceptor(client)
                async with llm_interceptor.intercept_response(scenario), fn_interceptor.intercept_response(scenario):
                    response = await client.process_query(test_messages)
                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)

            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }

class MCPLLMInjectionToResponseChain(MCPAttack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/two_step_chained/test_llm_injections/test_chain_llm_injection_to_response_injection.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    async def execute(self,client, messages,llm_judge):
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm_asyncio(
            self.scenarios,
            desc="Testing llm injection -> response injection chain",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

        async for scenario in progress_bar:
            try:
                test_messages = deepcopy(messages)
                test_messages.append({
                    "role": "user",
                    "content": scenario.initial_user_prompt
                })

                llm_interceptor = LLMModifier(client)
                response_interceptor = ResponseInjectionInterceptor(client)
                async with llm_interceptor.intercept_response(scenario), response_interceptor.intercept_response(scenario):
                    response = await client.process_query(test_messages)
                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)

            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }

