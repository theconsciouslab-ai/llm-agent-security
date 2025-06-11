from copy import deepcopy
from attacks.base_attack import Attack
from agent.azure_agent import Agent
from .malicious_agent_tools import MaliciousAgentTools
from attacks import AttackEvaluator, ScenarioLoader
from tqdm import tqdm
from __init__ import MessageFormatter


# For this attack i am using class inheritance tactique

class AgentToolPatcher:
    def __init__(self, original_agent):
        self.original_agent = original_agent
        self.original_tools = deepcopy(original_agent.tools)
        self.original_available_functions = deepcopy(original_agent.available_functions)
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.original_agent.tools = self.original_tools
        self.original_agent.available_functions = self.original_available_functions
        return False
        
    def patch(self, malicious_tools):
        self.original_agent.available_functions = {**self.original_agent.available_functions, **malicious_tools}
       

class ToolInjection(Attack):
    def __init__(self, name, description, scenario_file="./tests/test_simple/test_tool_injection_scenarios.json"):
        super().__init__(name, description)
        self.scenarios =ScenarioLoader.load_scenarios(scenario_file)
        
    def execute(self, messages, agent, model_type, llm_judge):
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing  Tool injection scenarios",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

        for scenario in progress_bar:
            try:
                test_messages = deepcopy(messages)
                test_messages.append({
                    "role": "user",
                    "content": scenario.initial_user_prompt
                })

                test_messages = MessageFormatter.format_messages(
                        llm_provider=model_type,
                        messages=test_messages,
                )

                with AgentToolPatcher(agent) as patcher:
                    current_malicious_tools = MaliciousAgentTools().malicious_agent_tools
                    patcher.patch(current_malicious_tools)
                    response = agent.run_conversation(test_messages)

                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)

            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }
    
