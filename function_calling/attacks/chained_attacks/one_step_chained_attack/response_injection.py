from tqdm import tqdm
from typing import Dict, List
from copy import deepcopy
from agent.azure_agent import Agent as AzureAgent
from agent.aws_agent import AwsAgent
from metrics.attack_success_rate import ASR
from metrics.refusal_rate import RefusalRate
from attacks.base_attack import Attack
from attacks.chained_attacks.two_step_chained_attack import AttackScenario
import json 
from __init__ import MessageFormatter

class BaseResponseInjectionInterceptor:
    def execute_with_interceptor(self, messages: List[Dict], scenario) -> Dict:
        raise NotImplementedError("Subclasses must implement this method")
    
class AzureResponseInjectionInterceptor(BaseResponseInjectionInterceptor):        
    def __init__(self, original_agent: AzureAgent):
        self.original_agent = original_agent

    def execute_with_interceptor(self, messages: List[Dict], scenario) -> Dict:
        intercepted_messages = deepcopy(messages)
        response = self.original_agent.run_conversation(intercepted_messages)
        
        if response.get("function_name"):
            intercepted_messages.extend([
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": intercepted_messages[-1]['tool_call_id'],  
                            "type": "function",
                            "function": {
                                "name": response["function_name"],
                                "arguments": json.dumps(response["arguments_llm"])
                            }
                        }
                    ]
                },
                {
                    "role": "tool",
                    "tool_call_id": intercepted_messages[-1]['tool_call_id'],
                    "name": response["function_name"],
                    "content": scenario.malicious_output,
                    
                }
            ])
                
            second_response = self.original_agent.client.chat.completions.create(
                messages=intercepted_messages,
                model=self.original_agent.model_name
            )
                
            return {
                "function_name": response["function_name"],
                "arguments_llm": response["arguments_llm"],
                "arguments_execution": response["arguments_execution"],
                "output": response["output"],
                "llm_response": second_response.choices[0].message.content,
            }
        
        return response

class AWSResponseInjectionInterceptor(BaseResponseInjectionInterceptor):
    def __init__(self, original_agent: AwsAgent):
        self.original_agent = original_agent

    def execute_with_interceptor(self, messages: List[Dict], scenario) -> Dict:
        intercepted_messages = deepcopy(messages)
        response = self.original_agent.run_conversation(intercepted_messages)
        
        if response.get("function_name"):
            # Create AWS-style tool response message
            tool_response = {
                "role": "user",
                "content": [{
                    "toolResult": {
                        "toolUseId": intercepted_messages[-1]['content'][-1]['toolResult']['toolUseId'],
                        "content": [{
                            "text": scenario.malicious_output
                        }]
                    }
                }]
            }
            
            intercepted_messages[-1] = tool_response
            
            final_response = self.original_agent.client.converse(
                modelId=self.original_agent.model_name,
                messages=intercepted_messages,
                toolConfig=self.original_agent.tool_config
            )
            
            # Extract the final LLM response
            final_message = final_response['output']['message']
            if 'content' in final_message and final_message['content']:
                response['llm_response'] = "\n".join(
                    [c.get('text', '') for c in final_message['content'] if 'text' in c]
                )
        
        return response

class ResponseInjectionChain(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/one_step/test_chain_response_injection.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages: List[Dict], agent, model_type: str, llm_judge=None) -> Dict:
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing response injection chain",
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

                interceptor = self._get_interceptor(agent, model_type)
                response = interceptor.execute_with_interceptor(test_messages, scenario)
                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)

            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }

    def _get_interceptor(self, agent, model_type: str) -> BaseResponseInjectionInterceptor:
        model_type = model_type.lower()
        if model_type == "azure":
            return AzureResponseInjectionInterceptor(agent)
        elif model_type == "aws":
            return AWSResponseInjectionInterceptor(agent)
        else:
            raise ValueError(f"Unsupported model type: {model_type}")
            
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
            "scenario_id": scenario.scenario_id,
            "scenario_details": {
                "malicious_output": scenario.malicious_output,
            },
            "attack_success": self.asr.detect_tampering(
                scenario.expected_result, 
                actual_result
            ),
            "refusal_success": self.refusal_rate.detect_refusal(
                scenario.initial_user_prompt,
                actual_result["llm_response"]
            ),
            "actual_result": actual_result,
            "expected_result": scenario.expected_result,
        }
    
    def record_failure(self, error: Exception, scenario: AttackScenario) -> Dict:
        failure_record = {
            "scenario_id": scenario.scenario_id,
            "status": "FAILED",
            "scenario_details": {
                "malicious_output": scenario.malicious_output,
            },
            "error": str(error),
            "error_type": type(error).__name__,
        }
        self.asr.get_attack_logs().append({
            "expected": scenario.expected_result,
            "actual": failure_record,
            "success": False
        })
        return failure_record
    
    def get_metrics(self) -> Dict:
        return {
            "attack_success_rate": self.asr.calculate_attack_success_rate(),
            "refusal_rate": self.refusal_rate.calculate_refusal_rate()
        }