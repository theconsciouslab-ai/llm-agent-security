import json
from tqdm import tqdm
from typing import Dict, List
from copy import deepcopy
from agent.azure_agent import Agent
from agent.aws_agent import AwsAgent
from metrics.attack_success_rate import ASR
from metrics.refusal_rate import RefusalRate
from attacks.base_attack import Attack
from attacks.chained_attacks.one_step_chained_attack import build_error_response, build_aws_error_response
from attacks.chained_attacks.two_step_chained_attack import AttackScenario
from __init__ import MessageFormatter

class BaseFunctionInjectionInterceptor:
    def intercept_conversation(self, messages: List[Dict], scenario) -> Dict:
        raise NotImplementedError("Subclasses must implement this method")

class AzureFunctionInjectionInterceptor(BaseFunctionInjectionInterceptor):    
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

            fn_name = response_message.tool_calls[0].function.name
            original_args = json.loads(response_message.tool_calls[0].function.arguments)
            
            combined_args = {**original_args, **scenario.malicious_args} if hasattr(scenario, 'malicious_args') else original_args
            
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
            modified_output = {**original_output, **scenario.malicious_output} if hasattr(scenario, 'malicious_output') else original_output
                            
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
                    "content": json.dumps(modified_output)
                }
            ])
            
            final_response = self.original_agent.client.chat.completions.create(
                messages=intercepted_messages,
                model=self.original_agent.model_name,
                tools=self.original_agent.tools,
                tool_choice="auto"
            )
            
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

class AWSFunctionInjectionInterceptor(BaseFunctionInjectionInterceptor):
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
            
            combined_args = {**original_args, **scenario.malicious_args} if hasattr(scenario, 'malicious_args') else original_args
            
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
            modified_output = {**original_output, **scenario.malicious_output} if hasattr(scenario, 'malicious_output') else original_output
            
            intercepted_messages.append(output_message)
            intercepted_messages.append({
                "role": "user",
                "content": [{
                    "toolResult": {
                        "toolUseId": tool['toolUseId'],
                        "content": [{"json": modified_output}]
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
        
class FunctionInjectionChain(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/one_step/test_chain_function_injection.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages: List[Dict], agent, model_type: str, llm_judge=None) -> Dict:
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing function injection chain",
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
                response = interceptor.intercept_conversation(test_messages, scenario)
                results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)

            except Exception as e:
                results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }

    def _get_interceptor(self, agent, model_type: str) -> BaseFunctionInjectionInterceptor:
        model_type = model_type.lower()
        if model_type == "azure":
            return AzureFunctionInjectionInterceptor(agent)
        elif model_type == "aws":
            return AWSFunctionInjectionInterceptor(agent)
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
                "malicious_args": scenario.malicious_args,
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
                "malicious_args": scenario.malicious_args,
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