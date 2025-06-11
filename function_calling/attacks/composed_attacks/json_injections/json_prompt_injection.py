from attacks.simple_attacks.prompt_injections.user_prompt_modification import UserInputModification

class JSONPromptInjectionAtUserLevel(UserInputModification):  
    def __init__(self, name, description, scenario_file="./tests/test_composed/test_json_prompt_injection_scenarios.json"):
        super().__init__(name, description, scenario_file)