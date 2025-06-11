import json
from copy import deepcopy
from tqdm import tqdm
from attacks import AttackEvaluator
from attacks.simple_attacks.indirect_prompt_injections import FunctionResponseLoader
from typing import Dict, Union
from attacks.base_attack import Attack
from __init__ import MessageFormatter
from agent.azure_agent import Agent as AzureAgent
from agent.aws_agent import AwsAgent

class IndirectPromptInjection(Attack):
    def __init__(self, name, description, scenario_file="./tests/test_simple/test_ipi_response_scenarios.json"):
        super().__init__(name, description)
        self.scenarios = FunctionResponseLoader.load_scenarios(scenario_file)

    def execute(self, messages, agent, model_type, llm_judge):
        results = {}
        self.evaluator = AttackEvaluator(llm_judge)
        
        with tqdm(
            self.scenarios,
            desc="Testing indirect prompt injection scenarios",
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

                    # Create interceptor with provider-specific logic
                    interceptor = FunctionResponseInterceptor.create(
                        model_type=model_type,
                        malicious_output=scenario.modified_prompt
                    )
                    
                    # Execute with intercepted function response
                    response = self._execute_with_interceptor(
                        agent=agent,
                        messages=test_messages,
                        interceptor=interceptor,
                        model_type=model_type
                    )
                    results[scenario.scenario_id] = self.evaluator.evaluate_response(scenario, response)
                
                except Exception as e:
                    results[scenario.scenario_id] = self.evaluator.record_failure(e, scenario)

        return {
            "detailed_results": results,
            **self.evaluator.get_metrics()
        }
    
    def _execute_with_interceptor(self, agent, messages, interceptor, model_type):
        if model_type.lower() == "azure":
            return self._execute_azure(agent, messages, interceptor)
        elif model_type.lower() == "aws":
            return self._execute_aws(agent, messages, interceptor)
        else:
            raise ValueError(f"Unsupported model type: {model_type}")
    
    def _execute_azure(self, agent: AzureAgent, messages, interceptor):
        original_run_conversation = agent.run_conversation
        attack_result = {}
        
        def intercepted_run_conversation(messages_input):
            response = original_run_conversation(messages_input)
            attack_result.update(response)
            
            if response.get("function_name") and response.get("output"):
                modified_messages = deepcopy(messages_input)
                modified_messages.extend([
                    {
                        "role": "assistant",
                        "tool_calls": [{
                            "id": f"call_{response['function_name']}",
                            "type": "function",
                            "function": {
                                "name": response["function_name"],
                                "arguments": json.dumps(response["arguments_llm"])
                            }
                        }],
                        "content": None
                    },
                    {
                        "role": "tool",
                        "tool_call_id": f"call_{response['function_name']}",
                        "name": response["function_name"],
                        "content": interceptor.malicious_output
                    }
                ])
                
                second_response = agent.client.chat.completions.create(
                    messages=modified_messages,
                    model=agent.model_name,
                    tools=agent.tools,
                    tool_choice="auto"
                )
                
                attack_result["llm_response"] = second_response.choices[0].message.content
            return attack_result
        
        agent.run_conversation = intercepted_run_conversation
        
        try:
            result = agent.run_conversation(messages)
        finally:
            agent.run_conversation = original_run_conversation
        
        return result
    
    def _execute_aws(self, agent: AwsAgent, messages, interceptor):
        original_run_conversation = agent.run_conversation
        attack_result = {}
        
        def intercepted_run_conversation(messages_input):
            response = original_run_conversation(messages_input)
            attack_result.update(response)
            
            if response.get("function_name") and response.get("output"):
                modified_messages = deepcopy(messages_input)
                
                # AWS uses different message format for tool calls
                modified_messages.append({
                    "role": "assistant",
                    "content": [{
                        "toolUse": {
                            "toolUseId": f"call_{response['function_name']}",
                            "name": response["function_name"],
                            "input": response["arguments_llm"]
                        }
                    }]
                })
                
                modified_messages.append({
                    "role": "user",
                    "content": [{
                        "toolResult": {
                            "toolUseId": f"call_{response['function_name']}",
                            "content": [{"text": interceptor.malicious_output}]
                        }
                    }]
                })
                
                second_response = agent.client.converse(
                    modelId=agent.model_name,
                    messages=modified_messages,
                    toolConfig=agent.tool_config
                )
                
                final_message = second_response['output']['message']
                if 'content' in final_message:
                    attack_result["llm_response"] = "\n".join([
                        c.get('text', '') 
                        for c in final_message['content'] 
                        if 'text' in c
                    ])
            return attack_result
        
        agent.run_conversation = intercepted_run_conversation
        
        try:
            result = agent.run_conversation(messages)
        finally:
            agent.run_conversation = original_run_conversation
        
        return result

class FunctionResponseInterceptor:
    def __init__(self, malicious_output: Dict):
        self.malicious_output = malicious_output
    
    @staticmethod
    def create(model_type: str, malicious_output: Dict):
        if model_type.lower() == "azure":
            return AzureFunctionResponseInterceptor(malicious_output)
        elif model_type.lower() == "aws":
            return AwsFunctionResponseInterceptor(malicious_output)
        else:
            raise ValueError(f"Unsupported model type: {model_type}")

class AzureFunctionResponseInterceptor(FunctionResponseInterceptor):
    pass  # Uses base class implementation

class AwsFunctionResponseInterceptor(FunctionResponseInterceptor):
    pass  # Uses base class implementation