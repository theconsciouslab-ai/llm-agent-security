from copy import deepcopy
from attacks.simple_attacks.tool_injections.tool_injection import ToolInjection

# For this attack i am using class inheritance tactique

class LoopCallingFunctionToolInjectionSameName(ToolInjection):
    def __init__(self, name, description, scenario_file="./tests/test_basic_scenarios.json"):
        super().__init__(name, description, scenario_file)
       