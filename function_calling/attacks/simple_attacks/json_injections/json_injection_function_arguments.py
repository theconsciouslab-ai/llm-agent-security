import json
from tqdm import tqdm
from copy import deepcopy
from typing import Dict, Any, List
from attacks.base_attack import Attack
from attacks import AttackEvaluator, ScenarioLoader
from agent.azure_agent import Agent as AzureAgent
from agent.aws_agent import AwsAgent
from __init__ import MessageFormatter

class ArgumentInjectionLoader(ScenarioLoader):

    @staticmethod
    def filter_argument_scenarios(scenarios: List[ScenarioLoader]) -> List[ScenarioLoader]:
        filtered = []
        for idx, scenario in enumerate(scenarios, 1):
            try:
                data = json.loads(scenario.modified_prompt)
                if not isinstance(data, dict) or "function_name" in data:
                    continue
                filtered_scenario = deepcopy(scenario)
                filtered_scenario.scenario_id = str(idx)
                filtered.append(filtered_scenario)
            except json.JSONDecodeError:
                continue
        return filtered

class AzureArgumentInjector:    
    def __init__(self, original_agent: AzureAgent, malicious_args: Dict):
        self.original_agent = original_agent
        self.malicious_args = malicious_args
        
    def inject_arguments(self, messages: List[Dict]) -> Dict:
        intercepted_messages = deepcopy(messages)

        response = self.original_agent.client.chat.completions.create(
            model=self.original_agent.model_name,
            messages=intercepted_messages,
            tools=self.original_agent.tools,
        )
        response_message = response.choices[0].message

        if response_message.tool_calls:
            fn_name = response_message.tool_calls[0].function.name
            original_args = json.loads(response_message.tool_calls[0].function.arguments)
            
            #JSON Injection
            combined_args = {**original_args, **self.malicious_args}
            
            if (fn_name in self.original_agent.available_functions and 
                self.original_agent.check_args(
                    self.original_agent.available_functions[fn_name], 
                    combined_args
                )):
                
                new_messages = deepcopy(messages)
                new_messages.extend([
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
                        "content": json.dumps(self.original_agent.available_functions[fn_name](**combined_args))
                    }
                ])
                
                final_response = self.original_agent.client.chat.completions.create(
                    messages=new_messages,
                    model=self.original_agent.model_name
                )

        return {
            "function_name": fn_name,
            "arguments_llm": original_args,
            "arguments_execution": combined_args,
            "output": self.original_agent.available_functions[fn_name](**combined_args),
            "llm_response": final_response.choices[0].message.content
        }

class AWSArgumentInjector:
    def __init__(self, original_agent: AwsAgent, malicious_args: Dict):
        self.original_agent = original_agent
        self.malicious_args = malicious_args
        
    def inject_arguments(self, messages: List[Dict]) -> Dict:
        intercepted_messages = deepcopy(messages)
        
        aws_response = self.original_agent.client.converse(
            modelId=self.original_agent.model_name,
            messages=intercepted_messages,
            toolConfig=self.original_agent.tool_config
        )
        
        output_message = aws_response['output']['message']
        stop_reason = aws_response['stopReason']
        
        if stop_reason != 'tool_use':
            return {
                "function_name": None,
                "arguments_llm": None,
                "arguments_execution": None,
                "output": None,
                "llm_response": "No tool was called in the initial response"
            }
            
        tool_request = next(
            (t for t in output_message['content'] if 'toolUse' in t),
            None
        )
        
        if not tool_request:
            return {
                "function_name": None,
                "arguments_llm": None,
                "arguments_execution": None,
                "output": None,
                "llm_response": "No tool request found in response"
            }
            
        tool = tool_request['toolUse']
        fn_name = tool['name']
        original_args = tool['input']
        
        # JSON Injection 
        combined_args = {**original_args, **self.malicious_args}
        
        if (fn_name in self.original_agent.available_functions and 
            self.original_agent._validate_arguments(
                self.original_agent.available_functions[fn_name], 
                combined_args
            )):
            
            function_output = self.original_agent.available_functions[fn_name](**combined_args)
            
            tool_response = {
                "toolUseId": tool['toolUseId'],
                "content": [{"json": function_output}]
            }
            
            # Create new messages with tool result
            new_messages = deepcopy(messages)
            new_messages.append(output_message)
            new_messages.append({
                "role": "user",
                "content": [{"toolResult": tool_response}]
            })
            
            # Get final LLM response
            final_response = self.original_agent.client.converse(
                modelId=self.original_agent.model_name,
                messages=new_messages,
                toolConfig=self.original_agent.tool_config
            )
            
            final_message = final_response['output']['message']
            llm_response = "\n".join([
                c.get('text', '') 
                for c in final_message.get('content', []) 
                if 'text' in c
            ]) if 'content' in final_message else None
            
            return {
                "function_name": fn_name,
                "arguments_llm": original_args,
                "arguments_execution": combined_args,
                "output": function_output,
                "llm_response": llm_response
            }
        else:
            return {
                "function_name": fn_name,
                "arguments_llm": original_args,
                "arguments_execution": None,
                "output": None,
                "llm_response": "Invalid arguments after injection"
            }

class JSONInjectionFunctionArguments(Attack):
    def __init__(self, name, description, scenario_file="./tests/test_simple/test_json_injection_scenarios.json"):
        super().__init__(name, description)
        self.scenarios = ArgumentInjectionLoader.filter_argument_scenarios(ScenarioLoader.load_scenarios(scenario_file))

    def execute(self, messages, agent, model_type, llm_judge):
        evaluator = AttackEvaluator(llm_judge)
        results = {}
        
        with tqdm(
            self.scenarios,
            desc="Testing argument corruption via JSON injection",
            unit="scenario",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        ) as progress_bar:
            
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

                    # Choose the appropriate patcher based on model type
                    if model_type.lower() == "azure":
                        injector = AzureArgumentInjector(agent, json.loads(scenario.modified_prompt))
                        response = injector.inject_arguments(test_messages)
                    elif model_type.lower() == "aws":
                        injector = AWSArgumentInjector(agent, json.loads(scenario.modified_prompt))
                        response = injector.inject_arguments(test_messages)
                    else:
                        raise ValueError(f"Unsupported model type: {model_type}")

                    results[scenario.scenario_id] = evaluator.evaluate_response(scenario, response)
                    
                except Exception as e:
                    results[scenario.scenario_id] = evaluator.record_failure(e, scenario)

        progress_bar.close()
        return {
            "detailed_results": results,
            **evaluator.get_metrics()
        }