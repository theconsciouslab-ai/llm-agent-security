from attacks.simple_attacks.prompt_injections.user_prompt_modification import UserInputModification

class LoopCallingFunctionAtUserLevel(UserInputModification):  
    def __init__(self, name, description, scenario_file="./tests/test_composed/test_loop_calling_scenarios.json"):
        super().__init__(name, description, scenario_file)