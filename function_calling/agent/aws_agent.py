import inspect
from models.aws_models import AWSModels
from agent.base_agent import BaseAgent


class AwsAgent(BaseAgent):
    def __init__(self, aws_access_key_id, aws_secret_access_key, region_name, model_name):
        super().__init__()
        self.aws_models = AWSModels(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name,
        )
        self.client = self.aws_models.create_aws_client()
        self.model_name = model_name

    def run_conversation(self, messages):
        try:
            response = {
                "function_name": None,
                "arguments_llm": None,
                "arguments_execution": None,
                "output": None,
                "llm_response": None
            }
            
            # Initial LLM call
            aws_response = self.client.converse(
                modelId=self.model_name,
                messages=messages,
                toolConfig=self.tool_config
            )
            
            output_message = aws_response['output']['message']
            messages.append(output_message)
            stop_reason = aws_response['stopReason']
            
            # Set initial LLM response
            if 'content' in output_message and output_message['content']:
                response['llm_response'] = "\n".join([c.get('text', '') for c in output_message['content'] if 'text' in c])
            
            if stop_reason == 'tool_use':
                tool_requests = output_message['content']
                for tool_request in tool_requests:
                    if 'toolUse' in tool_request:
                        tool = tool_request['toolUse']
                        function_name = tool['name']
                        response['function_name'] = function_name
                        response['arguments_llm'] = tool['input']
                        
                        if function_name in self.available_functions:
                            function_to_call = self.available_functions[function_name]
                            function_args = tool['input']
                            
                            # Verify arguments
                            if not self._validate_arguments(function_to_call, function_args):
                                tool_response = {
                                    "toolUseId": tool['toolUseId'],
                                    "content": [{"text": "Invalid arguments provided"}],
                                    "status": "error"
                                }
                                response['llm_response'] = "Invalid arguments provided"
                            else:
                                function_output = function_to_call(**function_args)
                                response['arguments_execution'] = function_args
                                response['output'] = function_output
                                
                                tool_response = {
                                    "toolUseId": tool['toolUseId'],
                                    "content": [{"json": function_output}]
                                }
                                
                                messages.append({
                                    "role": "user",
                                    "content": [{"toolResult": tool_response}]
                                })
                                
                                # Get final LLM response after tool use
                                final_response = self.client.converse(
                                    modelId=self.model_name,
                                    messages=messages,
                                    toolConfig=self.tool_config
                                )
                                final_message = final_response['output']['message']
                                if 'content' in final_message and final_message['content']:
                                    response['llm_response'] = "\n".join([c.get('text', '') for c in final_message['content'] if 'text' in c])
            
            return response

        except Exception as e:
            return {
                "function_name": None,
                "arguments_llm": None,
                "arguments_execution": None,
                "output": None,
                "llm_response": f"An error occurred during processing: {str(e)}"
            }

    def _validate_arguments(self, function, args):
        sig = inspect.signature(function)
        params = sig.parameters

        for name, param in params.items():
            if param.default is param.empty and name not in args:
                return False
        
        for name in args:
            if name not in params:
                return False
                
        return True