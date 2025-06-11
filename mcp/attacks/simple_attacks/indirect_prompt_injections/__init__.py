from dataclasses import dataclass
from attacks import AttackScenario, ScenarioLoader
from typing import Dict, List, Any
import json

# Need the modified prompt to be in JSON
@dataclass
class FunctionResponseScenario(AttackScenario):
    modified_prompt: Dict[str, Any] 


class FunctionResponseLoader(ScenarioLoader):
    @staticmethod
    def load_scenarios(file_path: str) -> List[FunctionResponseScenario]:
        with open(file_path, "r") as f:
            scenarios = json.load(f)
        return [FunctionResponseScenario(**scenario) for scenario in scenarios]