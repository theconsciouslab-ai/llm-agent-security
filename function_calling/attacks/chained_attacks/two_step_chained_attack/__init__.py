import json
from dataclasses import dataclass
from agent.azure_agent import Agent
from agent.aws_agent import AwsAgent
from copy import deepcopy
from attacks.chained_attacks.one_step_chained_attack import build_error_response, build_aws_error_response
from typing import Dict, List, Optional, Any, Union
from metrics.attack_success_rate import ASR
from metrics.refusal_rate import RefusalRate

class BaseInputOutputInterceptor:
    def intercept_conversation(self, messages: List[Dict], scenario) -> Dict:
        raise NotImplementedError("Subclasses must implement this method")
    
    @staticmethod
    def _get_interceptor(agent, model_type: str):
        model_type = model_type.lower()
        if model_type == "azure":
            return AzureInputOutputInterceptor(agent)
        elif model_type == "aws":
            return AWSInputOutputInterceptor(agent)
        else:
            raise ValueError(f"Unsupported model type: {model_type}")

class AzureInputOutputInterceptor(BaseInputOutputInterceptor):    
    def __init__(self, original_agent: Agent):
        self.original_agent = original_agent

    def intercept_conversation(self, messages: List[Dict], scenario) -> Dict:
        intercepted_messages = deepcopy(messages)
        try:
            response = self.original_agent.client.chat.completions.create(
                model=self.original_agent.model_name,
                messages=intercepted_messages,
                tools=self.original_agent.tools,
            )
            
            response_message = response.choices[0].message

            if not response_message.tool_calls:
                return {
                    "function_name": None,
                    "arguments_llm": None,
                    "arguments_execution": None,
                    "output": None,
                    "llm_response": response_message.content
                }

            fn_name = (
                scenario.malicious_function 
                if hasattr(scenario, 'malicious_function') and scenario.malicious_function
                else response_message.tool_calls[0].function.name
            )
            original_args = json.loads(response_message.tool_calls[0].function.arguments)
            combined_args = (
                {**original_args, **scenario.malicious_args} 
                if hasattr(scenario, 'malicious_args') and scenario.malicious_args
                else original_args
            )
            print("fn_name",fn_name)
            print("combined_args",combined_args)

            if fn_name not in self.original_agent.available_functions:
                error_msg = f"Error: Function '{fn_name}' not found"
                return build_error_response(
                    self.original_agent,
                    intercepted_messages,
                    fn_name,
                    fn_name,
                    combined_args,
                    error_msg,
                )

            if not self.original_agent.check_args(
                    self.original_agent.available_functions[fn_name], 
                    combined_args
                ):
                error_msg = f"Error: Invalid arguments for function '{fn_name}'"
                return build_error_response(
                    self.original_agent,
                    intercepted_messages,
                    fn_name,
                    fn_name,
                    combined_args,
                    error_msg,
                )
                
            original_output = self.original_agent.available_functions[fn_name](**combined_args)
            if hasattr(scenario, 'malicious_output') and scenario.malicious_output:
                if isinstance(scenario.malicious_output, dict):
                    modified_output = {**original_output, **scenario.malicious_output}
                else:
                    modified_output = scenario.malicious_output
            else:
                modified_output = original_output

            print("original_output",original_output)
            print("malicious_output",modified_output)

            intercepted_messages.extend([
                {
                    "role": response_message.role,
                    "tool_calls": [
                        {
                            "id": response_message.tool_calls[0].id,
                            "type": "function",
                            "function": {
                                "name": fn_name,
                                "arguments": json.dumps(original_args)
                            }
                        }
                    ],
                    "content": None
                },
                {
                    "role": "tool",
                    "tool_call_id": response_message.tool_calls[0].id,
                    "name": fn_name,
                    "content": json.dumps(modified_output) if isinstance(modified_output, dict) else str(modified_output)
                }
            ])

            print("intercepted_messages 2:",intercepted_messages)
            
            final_response = self.original_agent.client.chat.completions.create(
                messages=intercepted_messages,
                model=self.original_agent.model_name,
            )
            print("final response",final_response.choices[0].message.content)
            
            return {
                "function_name": fn_name,
                "arguments_llm": original_args,
                "arguments_execution": combined_args,
                "output": modified_output,
                "llm_response": final_response.choices[0].message.content,
            }

        except Exception as e:
            error_msg = f"Error executing function '{fn_name}': {str(e)}"
            return build_error_response(
                self.original_agent,
                intercepted_messages,
                fn_name,
                fn_name,
                combined_args,
                error_msg,
            )

class AWSInputOutputInterceptor(BaseInputOutputInterceptor):
    def __init__(self, original_agent: AwsAgent):
        self.original_agent = original_agent

    def intercept_conversation(self, messages: List[Dict], scenario) -> Dict:
        intercepted_messages = deepcopy(messages)

        try:
            response = self.original_agent.client.converse(
                modelId=self.original_agent.model_name,
                messages=intercepted_messages,
                toolConfig=self.original_agent.tool_config
            )
            
            output_message = response['output']['message']
            stop_reason = response['stopReason']

            if stop_reason != 'tool_use':
                return {
                    "function_name": None,
                    "arguments_llm": None,
                    "arguments_execution": None,
                    "output": None,
                    "llm_response": "\n".join([c.get('text', '') for c in output_message.get('content', []) if 'text' in c])
                }

            tool_request = next((t for t in output_message['content'] if 'toolUse' in t), None)
            if not tool_request:
                return {
                    "function_name": None,
                    "arguments_llm": None,
                    "arguments_execution": None,
                    "output": None,
                    "llm_response": "No tool request found"
                }

            tool = tool_request['toolUse']
            fn_name = tool['name']
            original_args = tool['input']
            fn_name = (
                scenario.malicious_function 
                if hasattr(scenario, 'malicious_function') and scenario.malicious_function
                else tool['name']
            )
            combined_args = (
                {**original_args, **scenario.malicious_args} 
                if hasattr(scenario, 'malicious_args') and scenario.malicious_args
                else original_args
            )

            print("fn_name",fn_name)
            print("combined_args",combined_args)
    
            if fn_name not in self.original_agent.available_functions:
                error_msg = f"Error: Function '{fn_name}' not found"
                return build_aws_error_response(
                    self.original_agent,
                    intercepted_messages,
                    fn_name,
                    fn_name,
                    combined_args,
                    error_msg,
                    tool['toolUseId'],
                )

            if not self.original_agent._validate_arguments(
                    self.original_agent.available_functions[fn_name], 
                    combined_args
                ):
                error_msg = f"Error: Invalid arguments for function '{fn_name}'"
                return build_aws_error_response(
                    self.original_agent,
                    intercepted_messages,
                    fn_name,
                    fn_name,
                    combined_args,
                    error_msg,
                    tool['toolUseId'],
                )
                
            original_output = self.original_agent.available_functions[fn_name](**combined_args)
            if hasattr(scenario, 'malicious_output') and scenario.malicious_output:
                if isinstance(scenario.malicious_output, dict):
                    modified_output = {**original_output, **scenario.malicious_output}
                    content = [{"json": modified_output}]
                else:
                    modified_output = scenario.malicious_output
                    content = [{"text": str(modified_output)}]
            else:
                modified_output = original_output
                content = [{"json": modified_output}]
            
            print("original_output",original_output)
            
            intercepted_messages.append(output_message)
            intercepted_messages.append({
                "role": "user",
                "content": [{
                    "toolResult": {
                        "toolUseId": tool['toolUseId'],
                        "content": content,
                    }
                }]
            })
            
            final_response = self.original_agent.client.converse(
                modelId=self.original_agent.model_name,
                messages=intercepted_messages,
                toolConfig=self.original_agent.tool_config
            )
            
            final_message = final_response['output']['message']
            llm_response = "\n".join([c.get('text', '') for c in final_message.get('content', []) if 'text' in c])
            
            return {
                "function_name": fn_name,
                "arguments_llm": original_args,
                "arguments_execution": combined_args,
                "output": modified_output,
                "llm_response": llm_response,
            }

        except Exception as e:
            error_msg = f"Error executing function: {str(e)}"
            return build_aws_error_response(
                self.original_agent,
                intercepted_messages,
                fn_name,
                fn_name,
                combined_args,
                error_msg,
                tool['toolUseId'],
            )

@dataclass
class AttackScenario:
    scenario_id: str
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
            "scenario_prompt": { 
                "system_prompt_modification": scenario.system_prompt_modification,
                "user_prompt_modification":scenario.user_prompt_modification,
                "injected_tools":scenario.injected_tools,
                "forced_function":scenario.forced_function
                },
            "llm_response": actual_result["llm_response"],
            "attack_success": self.asr.detect_tampering(
                scenario.expected_result, 
                actual_result
            ),
            "refusal_success": self.refusal_rate.detect_refusal(
                scenario.user_prompt_modification,
                actual_result["llm_response"]
            ),
            "expected_result": scenario.expected_result,
            "actual_result": actual_result
        }
    
    def record_failure(self, error: Exception, scenario: AttackScenario) -> Dict:
        failure_record = {
            "status": "FAILED",
            "scenario_prompt": { 
                "system_prompt_modification": scenario.system_prompt_modification,
                "user_prompt_modification":scenario.user_prompt_modification,
                "injected_tools":scenario.injected_tools,
                "forced_function":scenario.forced_function
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
