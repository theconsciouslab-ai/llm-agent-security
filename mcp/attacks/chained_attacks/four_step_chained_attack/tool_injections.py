# This attack is three step chain attack:
# Starting point: tool_injection  

from copy import deepcopy
from tqdm.asyncio import tqdm_asyncio
from attacks.mcp_base_attack import MCPAttack
from attacks.chained_attacks.two_step_chained_attack import ScenarioLoader, AttackEvaluator
from attacks.chained_attacks.one_step_chained_attack.tool_injection import ToolInjector

from attacks.chained_attacks.one_step_chained_attack.llm_injection import LLMModifier
from attacks.chained_attacks.one_step_chained_attack.function_injection import FunctionInjectionInterceptor
from attacks.chained_attacks.one_step_chained_attack.response_injection import ResponseInjectionInterceptor

from dotenv import load_dotenv
import os 

load_dotenv()
MALICIOUS_SERVER_PATH = os.getenv('MALICIOUS_SERVER_PATH')

class MCPToolInjectionToLLMToFunctionToResponseChain(MCPAttack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/four_step_chained/test_tool_injections/test_chain_tool_injection_to_llm_to_function_to_response.json"):
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
                desc="Testing tool injection -> llm injection -> function injection -> response injection",
                unit="scenario",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
            )

            tool_interceptor = ToolInjector(client)
            await tool_interceptor.switch_server(MALICIOUS_SERVER_PATH)

            async for scenario in progress_bar:
                try:
                    test_messages = deepcopy(messages)
                    test_messages.append({
                        "role": "user",
                        "content": scenario.initial_user_prompt
                    })

                    llm_interceptor = LLMModifier(client)
                    fn_interceptor = FunctionInjectionInterceptor(client)
                    response_interceptor = ResponseInjectionInterceptor(client)
                    async with tool_interceptor.injection_context(scenario) ,llm_interceptor.intercept_response(scenario), fn_interceptor.intercept_response(scenario),  response_interceptor.intercept_response(scenario):
                        response = await client.process_query(test_messages)
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
