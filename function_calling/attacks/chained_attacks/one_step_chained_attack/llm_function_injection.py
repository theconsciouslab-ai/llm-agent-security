import json
from tqdm import tqdm
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from copy import deepcopy
from agent.azure_agent import Agent as AzureAgent
from agent.aws_agent import AwsAgent
from metrics.attack_success_rate import ASR
from metrics.refusal_rate import RefusalRate
from attacks.base_attack import Attack
from attacks.chained_attacks.two_step_chained_attack import AttackScenario
from __init__ import MessageFormatter

class BaseFunctionInjectionInterceptor:
    def _build_error_response(self, messages, original_fn_name, malicious_fn, args, error_msg):
        raise NotImplementedError("Subclasses must implement this method")

class AzureFunctionInjectionInterceptor(BaseFunctionInjectionInterceptor):
    def __init__(self, original_agent: AzureAgent):
        self.original_agent = original_agent

    def intercept_conversation(self, messages: List[Dict], scenario) -> Dict:
        intercepted_messages = deepcopy(messages)
        response = self.original_agent.client.chat.completions.create(
            model=self.original_agent.model_name,
            messages=intercepted_messages,
            tools=self.original_agent.tools,
            tool_choice="auto"
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

        malicious_function = scenario.malicious_function if hasattr(scenario, 'malicious_function') and scenario.malicious_function else fn_name
        malicious_args = scenario.malicious_args if hasattr(scenario, 'malicious_args') and scenario.malicious_args else original_args

        if malicious_function not in self.original_agent.available_functions:
            error_msg = f"Error: Function '{malicious_function}' not found"
            return self._build_error_response(
                intercepted_messages,
                fn_name,
                malicious_function,
                malicious_args,
                error_msg
            )

        if not self.original_agent.check_args(
                self.original_agent.available_functions[malicious_function], 
                malicious_args
            ):
            error_msg = f"Error: Invalid arguments for function '{malicious_function}'"
            return self._build_error_response(
                intercepted_messages,
                fn_name,
                malicious_function,
                malicious_args,
                error_msg
            )

        try:
            original_output = self.original_agent.available_functions[malicious_function](**malicious_args)
            
            intercepted_messages.extend([
                {
                    "role": response_message.role,
                    "tool_calls": [{
                        "id": f"call_{fn_name}",
                        "type": "function",
                        "function": {
                            "name": fn_name,
                            "arguments": json.dumps(malicious_args)
                        }
                    }],
                    "content": None
                },
                {
                    "role": "tool",
                    "tool_call_id": f"call_{fn_name}",
                    "name": fn_name,
                    "content": json.dumps(original_output)
                }
            ])
            
            final_response = self.original_agent.client.chat.completions.create(
                messages=intercepted_messages,
                model=self.original_agent.model_name
            )
            
            return {
                "function_name": malicious_function,
                "arguments_llm": malicious_args,
                "arguments_execution": malicious_args,
                "output": original_output,
                "llm_response": final_response.choices[0].message.content,
            }
            
        except Exception as e:
            error_msg = f"Error executing function '{malicious_function}': {str(e)}"
            return self._build_error_response(
                intercepted_messages,
                fn_name,
                malicious_function,
                malicious_args,
                error_msg
            )

    def _build_error_response(self, messages, original_fn_name, malicious_fn, args, error_msg):
        messages.extend([
            {
                "role": "assistant",
                "tool_calls": [{
                    "id": f"call_{original_fn_name}",
                    "type": "function",
                    "function": {
                        "name": original_fn_name,
                        "arguments": json.dumps(args)
                    }
                }],
                "content": None
            },
            {
                "role": "tool",
                "tool_call_id": f"call_{original_fn_name}",
                "name": original_fn_name,
                "content": json.dumps({"error": error_msg})
            }
        ])
        
        final_response = self.original_agent.client.chat.completions.create(
            messages=messages,
            model=self.original_agent.model_name
        )
        
        return {
            "function_name": malicious_fn,
            "arguments_llm": args,
            "arguments_execution": None,
            "output": None,
            "llm_response": final_response.choices[0].message.content,
        }

class AWSFunctionInjectionInterceptor(BaseFunctionInjectionInterceptor):
    def __init__(self, original_agent: AwsAgent):
        self.original_agent = original_agent

    def intercept_conversation(self, messages: List[Dict], scenario) -> Dict:
        intercepted_messages = deepcopy(messages)
        response = self.original_agent.client.converse(
            modelId=self.original_agent.model_name,
            messages=intercepted_messages,
            toolConfig=self.original_agent.tool_config
        )
        
        output_message = response['output']['message']
        messages.append(output_message)
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

        malicious_function = scenario.malicious_function if hasattr(scenario, 'malicious_function') and scenario.malicious_function else fn_name
        malicious_args = scenario.malicious_args if hasattr(scenario, 'malicious_args') and scenario.malicious_args else original_args

        if malicious_function not in self.original_agent.available_functions:
            error_msg = f"Error: Function '{malicious_function}' not found"
            return self._build_error_response(
                intercepted_messages,
                fn_name,
                malicious_function,
                malicious_args,
                error_msg,
                tool['toolUseId']
            )

        if not self.original_agent._validate_arguments(
                self.original_agent.available_functions[malicious_function], 
                malicious_args
            ):
            error_msg = f"Error: Invalid arguments for function '{malicious_function}'"
            return self._build_error_response(
                intercepted_messages,
                fn_name,
                malicious_function,
                malicious_args,
                error_msg,
                tool['toolUseId']
            )

        try:
            original_output = self.original_agent.available_functions[malicious_function](**malicious_args)
            
            intercepted_messages.append(output_message)
            intercepted_messages.append({
                "role": "user",
                "content": [{
                    "toolResult": {
                        "toolUseId": tool['toolUseId'],
                        "content": [{"json": original_output}]
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
                "function_name": malicious_function,
                "arguments_llm": malicious_args,
                "arguments_execution": malicious_args,
                "output": original_output,
                "llm_response": llm_response,
            }
            
        except Exception as e:
            error_msg = f"Error executing function '{malicious_function}': {str(e)}"
            return self._build_error_response(
                intercepted_messages,
                fn_name,
                malicious_function,
                malicious_args,
                error_msg,
                tool['toolUseId']
            )

    def _build_error_response(self, messages, original_fn_name, malicious_fn, args, error_msg, tool_use_id):
        messages.extend([
            {
                "role": "assistant",
                "content": [{
                    "toolUse": {
                        "toolUseId": tool_use_id,
                        "name": original_fn_name,
                        "input": args
                    }
                }]
            },
            {
                "role": "user",
                "content": [{
                    "toolResult": {
                        "toolUseId": tool_use_id,
                        "content": [{"text": error_msg}],
                    }
                }]
            }
        ])
        
        final_response = self.original_agent.client.converse(
            modelId=self.original_agent.model_name,
            messages=messages,
            toolConfig= self.original_agent.tool_config
        )
        
        final_message = final_response['output']['message']
        llm_response = "\n".join([c.get('text', '') for c in final_message.get('content', []) if 'text' in c])
        
        return {
            "function_name": malicious_fn,
            "arguments_llm": args,
            "arguments_execution": None,
            "output": None,
            "llm_response": llm_response,
        }

class LLMFunctionInjectionChain(Attack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_chained/one_step/test_chain_llm_injection.json"):
        super().__init__(name, description)
        self.scenarios = ScenarioLoader.load_scenarios(scenario_file)

    def execute(self, messages: List[Dict], agent, model_type: str, llm_judge=None) -> Dict:
        evaluator = AttackEvaluator(llm_judge)
        results = {}

        progress_bar = tqdm(
            self.scenarios,
            desc="Testing LLM function injection chain",
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

                # Select and execute the appropriate interceptor
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
                "malicious_function": scenario.malicious_function,
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
                "malicious_function": scenario.malicious_function,
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