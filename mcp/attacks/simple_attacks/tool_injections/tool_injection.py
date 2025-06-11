import os
from attacks.mcp_base_attack import MCPAttack
from attacks import ScenarioLoader, AttackEvaluator
from tqdm.asyncio import tqdm_asyncio

class MCPToolInjection(MCPAttack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_simple/test_tool_injection_scenarios.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)
    
    async def execute(self,client, messages,llm_judge):
        results = {}
        self.evaluator = AttackEvaluator(llm_judge)

        progress_bar = tqdm_asyncio(
            self.scenarios,
            desc="Tools Injection Scenarios",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )
            

        async for scenario in progress_bar:
            
            try:
                messages.append({
                    "role": "user",
                    "content": scenario.initial_user_prompt
                })

                response = await client.process_query(messages)
                results[scenario.scenario_id] = self.evaluator.evaluate_response(scenario, response)

            except Exception as e:
                results[scenario.scenario_id] = self.evaluator.record_failure(e, scenario)

        #progress_bar.close()

        return {
            "detailed_results": results,
            **self.evaluator.get_metrics()
        }