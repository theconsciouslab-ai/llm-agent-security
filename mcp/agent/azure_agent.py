import json
import asyncio
import json
from models.azure_models import Azure_models
from agent.base_agent import BaseAgent
from __init__ import MessageFormatter


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
    
    async def run_conversation(self, messages, session,timeout):
        messages = MessageFormatter.format_messages(
            llm_provider="azure",
            messages= messages,
        )
        list_tools_task = session.list_tools()
        tool_list = await asyncio.wait_for(list_tools_task, timeout=timeout)

        available_tools = [{
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.inputSchema
                }
        } for tool in tool_list.tools]

        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            tools=available_tools,
            tool_choice="auto"
        )

        response_message = response.choices[0].message
        function_name = None
        arguments_llm = None
        arguments_execution = None
        tool_content_text = None
        llm_response = response_message.content

        tool_calls = response_message.tool_calls

        if tool_calls:
            for tool_call in tool_calls:
                function_name = tool_call.function.name
                arguments_llm = tool_call.function.arguments
                function_args = json.loads(arguments_llm)

                try:
                    tool_response = await session.call_tool(function_name, function_args)
                    tool_content_text = tool_response.content[0].text

                    messages.append({
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": tool_call.id,
                                    "type": "function",
                                    "function": {
                                        "name": function_name,
                                        "arguments": json.dumps(function_args)
                                    }
                                }
                            ]
                    })

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": function_name,
                        "content": json.dumps(tool_content_text)
                    })

                except Exception as e:
                    print(f"Tool execution error: {e}")
                    raise

            second_response = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
            )

            second_message = second_response.choices[0].message
            if second_message.content:
                llm_response = second_message.content
        return {
                "function_name": function_name,
                "arguments_llm": json.loads(arguments_llm) if arguments_llm else None,
                "arguments_execution": function_args if 'function_args' in locals() else None,
                "output": (json.loads(tool_content_text) if tool_content_text else None) if isinstance(tool_content_text, str) and tool_content_text.strip().startswith(("{", "[", "\"")) else tool_content_text,
                "llm_response": llm_response
        }
