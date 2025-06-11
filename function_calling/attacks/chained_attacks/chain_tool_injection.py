from tqdm import tqdm
from attacks.base_attack import Attack
from attacks.simple_attacks.tool_injections.malicious_agent_tools import MaliciousAgentTools
from attacks.simple_attacks.prompt_injections.system_prompt_modification import SystemPromptModifier
from attacks import ScenarioLoader, AttackEvaluator
from attacks.simple_attacks.tool_injections.tool_injection import AgentToolPatcher


class ToolInjectionChain(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chain.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages, agent, llm_judge):
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing scenarios chained injection tool attacks",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

        for scenario in progress_bar:
            try:
                modified_messages = SystemPromptModifier.modify_system_prompt(messages, scenario.modified_prompt)
                modified_messages.append({
                    "role": "user",
                    "content": scenario.initial_user_prompt
                })

                with AgentToolPatcher(agent) as patcher:
                    current_malicious_tools = MaliciousAgentTools().malicious_agent_tools
                    patcher.patch(current_malicious_tools)
                    response = agent.run_agent_conversation(modified_messages)

                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)

            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }