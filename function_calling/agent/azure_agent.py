import json
import inspect
from models.azure_models import Azure_models
from agent.base_agent import BaseAgent


class Agent(BaseAgent):
    def __init__(self, api_key, endpoint, api_version, model_name):
        
        super().__init__()

        self.azure_models = Azure_models(
            api_key=api_key,
            endpoint=endpoint,
            api_version=api_version,
            sdk_type = "azure_openai_sdk"

        )

        self.client = self.azure_models.create_azure_openai_client()
        
        self.model_name = model_name
        self.api_key = api_key
        self.azure_endpoint = endpoint
        self.api_version = api_version


    # Helper function to validate function arguments
    def check_args(self,function, args):
        sig = inspect.signature(function)
        params = sig.parameters

        for name in args:
            if name not in params:
                return False

        for name, param in params.items():
            if param.default is param.empty and name not in args:
                return False
        return True

    def run_conversation(self, messages):
        # Step 1: Send the conversation and available functions to the LLM
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            tools=self.tools,
            tool_choice="auto"
        )

        response_message = response.choices[0].message
        function_name = None
        arguments_llm = None
        arguments_execution = None
        output = None
        llm_response = response_message.content

        # Step 2: Check if the LLM wants to call a function
        if response_message.tool_calls:

            # Step 3: Extract function name and arguments
            function_name = response_message.tool_calls[0].function.name
            arguments_llm = json.loads(response_message.tool_calls[0].function.arguments)

            # Verify function exists
            if function_name not in self.available_functions:
                return {
                    "function_name": function_name,
                    "arguments_llm": arguments_llm,
                    "arguments_execution": None,
                    "output": None,
                    "llm_response": f"Function {function_name} does not exist"
                }

            function_to_call = self.available_functions[function_name]

            # Verify function arguments
            if not self.check_args(function_to_call, arguments_llm):
                return {
                    "function_name": function_name,
                    "arguments_llm": arguments_llm,
                    "arguments_execution": None,
                    "output": None,
                    "llm_response": f"Invalid number of arguments for function: {function_name}"
                }

            # Step 3: Call the function

            output = function_to_call(**arguments_llm)
            arguments_execution = arguments_llm  # Assuming arguments do not change

            # Step 4: Send the function response back to the LLM
            messages.append({
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                "id": response_message.tool_calls[0].id,
                                    "type": "function",
                                    "function": {
                                        "name": function_name,
                                        "arguments": json.dumps(arguments_llm)
                                    }
                                }
                            ]
                        })
            messages.append({
                            "role": "tool",
                            "tool_call_id": response_message.tool_calls[0].id,
                            "name": function_name,
                            "content": json.dumps(output)
            })

            # Step 5: Get a new response from the LLM with the function response
            second_response = self.client.chat.completions.create(
                messages=messages,
                model=self.model_name,
            )

            second_message = second_response.choices[0].message

            if second_message.content:
                llm_response = second_message.content

        return {
            "function_name": function_name,
            "arguments_llm": arguments_llm,
            "arguments_execution": arguments_execution,
            "output": output,
            "llm_response": llm_response
        }
    