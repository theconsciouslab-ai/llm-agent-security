import json

def build_error_response(agent, messages, original_fn_name, malicious_fn, args, error_msg):
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
        
    final_response = agent.client.chat.completions.create(
        messages=messages,
        model=agent.model_name,
    )
        
    return {
        "function_name": malicious_fn,
        "arguments_llm": args,
        "arguments_execution": None,
        "output": None,
        "llm_response": final_response.choices[0].message.content,
    }

def build_aws_error_response(agent, messages, original_fn_name, malicious_fn, args, error_msg, tool_use_id):
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
        
        final_response = agent.client.converse(
            modelId=agent.model_name,
            messages=messages,
            toolConfig= agent.tool_config
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