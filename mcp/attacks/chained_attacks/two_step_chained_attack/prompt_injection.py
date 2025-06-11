# This attack is two step chain attack :
# Starting point Prompt

from tqdm.asyncio import tqdm_asyncio
from copy import deepcopy
from dotenv import load_dotenv
import os
from attacks.mcp_base_attack import MCPAttack
from attacks.chained_attacks.two_step_chained_attack import ScenarioLoader, AttackEvaluator
from attacks.chained_attacks.one_step_chained_attack.prompt_injection import PromptInjector

from attacks.chained_attacks.one_step_chained_attack.tool_injection import ToolInjector
from attacks.chained_attacks.one_step_chained_attack.llm_injection import LLMModifier
from attacks.chained_attacks.one_step_chained_attack.function_injection import FunctionInjectionInterceptor
from attacks.chained_attacks.one_step_chained_attack.response_injection import ResponseInjectionInterceptor


load_dotenv()

MALICIOUS_SERVER_PATH = os.getenv('MALICIOUS_SERVER_PATH')


class MCPPromptInjectionToTooChain(MCPAttack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/two_step_chained/test_prompt_injections/test_chain_prompt_injection_to_api.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    async def execute(self,client, messages,llm_judge):
        evaluator = AttackEvaluator(llm_judge)
        results = {}
        was_connected = client.session is not None

        try: 
            if was_connected:
                original_server = getattr(client, 'current_server', None)
                await client.cleanup()

            progress_bar = tqdm_asyncio(
                self.scenarios,
                desc="Testing prompt injection -> tool injection chain",
                unit="scenario",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
            )

            interceptor = ToolInjector(client)
            await interceptor.switch_server(MALICIOUS_SERVER_PATH)
            
            async for scenario in progress_bar:
                try:
                    scenario_messages = deepcopy(messages)
                    modified_messages = PromptInjector(scenario_messages).inject_prompt(scenario)
                    async with interceptor.injection_context(scenario):
                        response = await client.process_query(modified_messages)
                    results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)

                except Exception as e:
                    results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        finally:
            if was_connected and original_server:
                try:
                    await client.connect_to_server(original_server)
                except Exception as e:
                    print(f"Warning: Failed to reconnect to original server: {e}")

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }
    
class MCPPromptInjectionToLLMChain(MCPAttack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/two_step_chained/test_prompt_injections/test_chain_prompt_injection_to_llm_function.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    async def execute(self,client, messages,llm_judge):
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm_asyncio(
                self.scenarios,
                desc="Testing prompt injection -> llm injection chain",
                unit="scenario",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
            )

        for scenario in progress_bar:
            try:
                scenario_messages = deepcopy(messages)
                modified_messages = PromptInjector(scenario_messages).inject_prompt(scenario)
                interceptor = LLMModifier(client)
                async with interceptor.intercept_response(scenario):
                    response = await client.process_query(modified_messages)
                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)

            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }
    
class MCPPromptInjectionToFunctionChain(MCPAttack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/two_step_chained/test_prompt_injections/test_chain_prompt_injection_to_function_injection.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    async def execute(self,client, messages,llm_judge):
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm_asyncio(
                self.scenarios,
                desc="Testing prompt injection -> function injection chain",
                unit="scenario",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
            )

        for scenario in progress_bar:
            try:
                scenario_messages = deepcopy(messages)
                modified_messages = PromptInjector(scenario_messages).inject_prompt(scenario)
                interceptor = FunctionInjectionInterceptor(client)
                async with interceptor.intercept_response(scenario):
                    response = await client.process_query(modified_messages)
                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)

            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }


class MCPPromptInjectionToResponseChain(MCPAttack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/two_step_chained/test_prompt_injections/test_chain_prompt_injection_to_response_injection.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    async def execute(self,client, messages,llm_judge):
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm_asyncio(
                self.scenarios,
                desc="Testing prompt injection -> response injection chain",
                unit="scenario",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
            )

        for scenario in progress_bar:
            try:
                scenario_messages = deepcopy(messages)
                modified_messages = PromptInjector(scenario_messages).inject_prompt(scenario)
                interceptor = ResponseInjectionInterceptor(client)
                async with interceptor.intercept_response(scenario):
                    response = await client.process_query(modified_messages)
                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)

            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }

