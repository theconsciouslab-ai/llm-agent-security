import asyncio
import json
from models.aws_models import AWSModels
from agent.base_agent import BaseAgent
from __init__ import MessageFormatter


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

    async def run_conversation(self, messages, session,timeout):
        messages = MessageFormatter.format_messages(
            llm_provider="aws",
            messages= messages,
        )
        try:
            list_tools_task = session.list_tools()
            tool_list = await asyncio.wait_for(list_tools_task, timeout=timeout)

            available_tools = [{
                "toolSpec":{
                    "name": tool.name,
                    "description": tool.description if tool.description else None,
                    "inputSchema": {"json": tool.inputSchema}
                } }for tool in tool_list.tools]

            response = {
                "function_name": None,
                "arguments_llm": None,
                "arguments_execution": None,
                "output": None,
                "llm_response": None
            }
                
            aws_response = self.client.converse(
                modelId=self.model_name,
                messages=messages,
                toolConfig= {"tools": available_tools} 
            )
                
            output_message = aws_response['output']['message']
            messages.append(output_message)
            stop_reason = aws_response['stopReason']
                
            if 'content' in output_message and output_message['content']:
                response['llm_response'] = "\n".join([c.get('text', '') for c in output_message['content'] if 'text' in c])
                
            if stop_reason == 'tool_use':
                for content in output_message['content']:
                    if 'toolUse' in content:
                        tool = content['toolUse']
                        function_name = tool['name']
                        arguments_llm = tool['input']

                        response.update({
                            'function_name': function_name,
                            'arguments_llm': arguments_llm
                        })

                        tool_response = await session.call_tool(function_name, arguments_llm)
                        response['arguments_execution'] = arguments_llm
                        
                        tool_content_text = tool_response.content[0].text
                        response['output'] = (json.loads(tool_content_text) if tool_content_text else None) if isinstance(tool_content_text, str) and tool_content_text.strip().startswith(("{", "[", "\"")) else tool_content_text

                        tool_result = {
                                "role": "user",
                                "content": [{
                                    "toolResult": {
                                        "toolUseId": tool['toolUseId'],
                                        "content": [{"text": tool_content_text}]
                                    }
                                }]
                        }
                        messages.append(tool_result)

                        final_response = self.client.converse(
                                modelId=self.model_name,
                                messages=messages,
                                toolConfig={"tools": available_tools} 
                        )
                        final_message = final_response['output']['message']
                        if 'content' in final_message and final_message['content']:
                            response['llm_response'] = "\n".join([c.get('text', '') for c in final_message['content'] if 'text' in c])
                
            return response
        except asyncio.TimeoutError:
            return {
                "llm_response": "Tool listing timed out",
                "error": "timeout"
            }
        except Exception as e:
            return {
                "llm_response": f"An error occurred: {str(e)}",
                "error": str(e)
            }
