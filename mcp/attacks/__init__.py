import json
from dataclasses import dataclass
from typing import Dict, List
from metrics.attack_success_rate import ASR
from metrics.refusal_rate import RefusalRate
from mcp_client.client import MCPClient
from dotenv import load_dotenv
import os

@dataclass
class AttackScenario:
    scenario_id: str
    initial_user_prompt: str
    modified_prompt: str
    expected_result: Dict

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
            "scenario_prompt": scenario.modified_prompt,
            "llm_response": actual_result["llm_response"],
            "attack_success": self.asr.detect_tampering(
                scenario.expected_result, 
                actual_result
            ),
            "refusal_success": self.refusal_rate.detect_refusal(
                scenario.modified_prompt,
                actual_result["llm_response"]
            ),
            "expected_result": scenario.expected_result,
            "actual_result": actual_result
        }
    
    def record_failure(self, error: Exception, scenario: AttackScenario) -> Dict:
        failure_record = {
            "status": "FAILED",
            "scenario_prompt": scenario.modified_prompt,
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
    

load_dotenv()

MALICIOUS_SERVER_PATH = os.getenv('MALICIOUS_SERVER_PATH')
LEGITIMATE_SERVER_PATH = os.getenv('LEGITIMATE_SERVER_PATH')


class ServerManager:
    def __init__(self):
        self.servers = {
            "legitimate": LEGITIMATE_SERVER_PATH,
            "malicious": MALICIOUS_SERVER_PATH
        }
    
    async def connect(self, client: MCPClient, attack_type: str) -> bool:
        try:
            await client.connect_to_server(self.servers["legitimate"], timeout=20)
            if attack_type == "tool_injection":
                await client.connect_to_server(self.servers["malicious"], timeout=20)
            return True
        except (TimeoutError, FileNotFoundError) as e:
            print(f"Server connection failed: {e}")
            return False