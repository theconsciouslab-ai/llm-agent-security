import json
from copy import deepcopy
from attacks.simple_attacks.prompt_injections.user_prompt_injection import MCPUserPromptModification

class MCPLoopCallingUserLevel(MCPUserPromptModification):  
    def __init__(self, name, description, scenario_file="./tests/test_composed/test_loop_calling_scenarios.json"):
        super().__init__(name, description, scenario_file)