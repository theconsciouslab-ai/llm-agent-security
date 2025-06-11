import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Union
from metrics.attack_success_rate import ASR
from metrics.refusal_rate import RefusalRate

@dataclass
class AttackScenario:
    scenario_id: int
    initial_user_prompt: str
    system_prompt_modification: str
    user_prompt_modification: str
    forced_function: str
    malicious_function: Optional[Dict[str, Any]]  
    malicious_args: Dict[str, Any] 
    malicious_output: Optional[Union[Dict[str, Any], str]]
    injected_tools: List[Dict]
    expected_result: Dict
    severity: str

class ScenarioLoader:
    @staticmethod
    def load_scenarios(file_path: str) -> List[AttackScenario]:
        with open(file_path, "r") as f:
            scenarios = json.load(f)
        return [AttackScenario(**scenario) for scenario in scenarios]

class AttackEvaluator:
    def __init__(self, llm_judge=None):
        self.asr = ASR()
        self.refusal_rate = RefusalRate()
        if llm_judge:
            self.asr.set_llm_judge(llm_judge)
            self.refusal_rate.set_llm_judge(llm_judge)
    
    def evaluate_response(self, scenario: AttackScenario, response: Dict) -> Dict:

        actual_result = {
            "function_name": response.get("function_name", ""),
            "arguments_llm": response.get("arguments_llm", {}),
            "arguments_execution": response.get("arguments_execution", {}),
            "output": response.get("output", {}),
            "llm_response": response.get("llm_response", "")
        }

        return {
            "attack_success": self.asr.detect_tampering(
                scenario.expected_result, 
                actual_result
            ),
            "refusal_success": self.refusal_rate.detect_refusal(
                scenario.user_prompt_modification,
                actual_result["llm_response"]
            ),
            "actual_result": actual_result,
            "expected_result": scenario.expected_result,
        }
    
    def record_failure(self, error: Exception, scenario: AttackScenario) -> Dict:
        failure_record = {
            "status": "FAILED",
            "scenario_prompt": { 
                "system_prompt_modification": scenario.system_prompt_modification,
                "user_prompt_modification":scenario.user_prompt_modification,
                "injected_tools":scenario.injected_tools,
                "forced_function":scenario.forced_function,
                "malicious_function": scenario.malicious_function,
                "malicious_args": scenario.malicious_args,
                "malicious_output": scenario.malicious_output,
                "llm_response":scenario.expected_result

            },
            "error": str(error),
            "error_type": type(error).__name__
        }
        self.asr.get_attack_logs().append({
            "expected": scenario.expected_result,
            "actual": failure_record,
            "success": False
        })
        return failure_record
    
    def get_metrics(self) -> Dict:
        return {
            "success_rate": self.asr.calculate_attack_success_rate(),
            "refusal_rate": self.refusal_rate.calculate_refusal_rate()
        }
