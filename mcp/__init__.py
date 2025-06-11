import json
import os
from datetime import datetime
from typing import List, Dict, Union
import pandas as pd
from config.config_loader import ConfigLoader


class ResultSaver:

    @staticmethod
    def save_test_results(model_name, attack_category, attack_type, test_results):
        runner = ConfigLoader()
        model_config = runner.get_model_config(model_name)
        experiment_config = runner.get_experiment_config()
        results_dir = f"results/{model_name}/{attack_category}"
        os.makedirs(results_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{results_dir}/{attack_type}_{timestamp}.json"
        
        result_data = {
            "model_name": model_name,
            "reasoning_capability": model_config.reasoning_capability,
            "model_provider":model_config.model_provider,
            "cloud_provider":model_config.model_type,
            "moderation_function":model_config.moderation_function,
            "safety_level":model_config.safety_level,
            "framework_used":experiment_config.framework_used,
            "judge_llm":experiment_config.judge_llm,
            "attacker_llm":experiment_config.attacker_llm,
            "attack_category": attack_category,
            "attack_type": attack_type,
            "timestamp": timestamp,
            "results": test_results,
        }
        
        with open(filename, 'w') as f:
            json.dump(result_data, f, indent=4)
        
        print(f"Results saved to: {filename}")
        return filename
    

    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! FOR TESTING ONLY !!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    @staticmethod
    def update_existing_results():
        runner = ConfigLoader()
        results_dir = "results"
        
        for root, _, files in os.walk(results_dir):
            for file in files:
                if file.endswith('.json'):
                    filepath = os.path.join(root, file)
                    
                    try:
                        with open(filepath, 'r') as f:
                            old_data = json.load(f)
                        
                        model_name = old_data['model_name']
                        model_config = runner.get_model_config(model_name)
                        experiment_config = runner.get_experiment_config()
                        
                        updated_data = {
                            **old_data,  
                            "reasoning_capability": model_config.reasoning_capability,
                            "model_provider": model_config.model_provider,
                            "cloud_provider": model_config.model_type,
                            "moderation_function": model_config.moderation_function,
                            "safety_level": model_config.safety_level,
                            "framework_used": experiment_config.framework_used,
                            "judge_llm": experiment_config.judge_llm,
                            "attacker_llm": experiment_config.attacker_llm
                        }
                        
                        with open(filepath, 'w') as f:
                            json.dump(updated_data, f, indent=4)
                            
                        print(f"Updated: {filepath}")
                        
                    except Exception as e:
                        print(f"Error updating {filepath}: {str(e)}")
    
    @staticmethod
    def generate_attack_analysis_excel(json_file_path):

        def safe_get(data, keys, default=None):
            current = data
            for key in keys:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return default
            return current
        
        with open(json_file_path, 'r') as f:
            data = json.load(f)

        attack_categories = {
            "simple_attacks": {
                "system_prompt_injection",
                "user_prompt_injection",
                "user_prompt_injection_instruction_bypass",
                "tool_choice_interception",
                "tools_interception",
                "json_injection_function_arguments",
                "indirect_prompt_injection",
                "tool_injection",
                "dos_attack",
            },
            "composed_attacks": {
                "loop_calling_system_level",
                "loop_calling_user_level",
                "loop_calling_user_level_instruction_based",
                "json_prompt_injection_user_level",
                "json_prompt_injection_user_level_instruction_based",
            },
            "chained_attacks": {
                "one_step_prompt_injection",
                "two_step_prompt_tool_chain",
                "three_step_prompt_tool_llm",
                "three_step_prompt_tool_function",
                "four_step_prompt_tool_llm_function",
                "five_step_prompt_tool_llm_function_response",
            }
        }

        rows = []

        for category, attack_types in attack_categories.items():
            category_asr = safe_get(data, ['results', 'stats', 'by_category', category, 'success_rate'])
            category_rr = safe_get(data, ['results', 'stats', 'by_category', category, 'refusal_rate'])
            
            if not safe_get(data, ['results', 'results', category]):
                continue
                
            for attack_name in attack_types:
                if not safe_get(data, ['results', 'results', category, attack_name]):
                    continue
                    
                attack_data = safe_get(data, ['results', 'results', category, attack_name], {})
                
                row = {
                    'Attack Name': attack_name,
                    'Attack Overall ASR': attack_data.get('success_rate'),
                    'Attack Overall RR': attack_data.get('refusal_rate'),
                    'Category': category.replace('_attacks', '').title(),
                    'Category Overall ASR': category_asr,
                    'Category Overall RR': category_rr,
                    'Attack Category': 'Simple' if 'simple' in category else 'Composed' if 'composed' in category else 'Chained',
                    'Overall ASR': safe_get(data, ['results', 'stats', 'success_rate_total']),
                    'Overall RR': safe_get(data, ['results', 'stats', 'refusal_rate_total']),
                    'LLM as Attacker': data.get('attacker_llm'),
                    'LLM as Judge': data.get('judge_llm'),
                    'Framework Used': data.get('framework_used'),
                    'Safety Level': data.get('safety_level'),
                    'Moderation Function': data.get('moderation_function'),
                    'Cloud Provider': data.get('cloud_provider'),
                    'Model Provider': data.get('model_provider'),
                    'Model Name': data.get('model_name')
                }
                rows.append(row)

        all_columns = [
            'Model Name', 'Model Provider', 'Cloud Provider', 'Moderation Function', 'Safety Level',
            'Framework Used', 'LLM as Judge', 'LLM as Attacker', 'Attack Category', 
            'Category Overall ASR', 'Category Overall RR', 'Attack Name',
            'Attack Overall ASR', 'Attack Overall RR'
        ]

        df = pd.DataFrame(rows)
        for col in all_columns:
            if col not in df.columns:
                df[col] = None

        df = df[all_columns]
        output_file_path = json_file_path.replace(".json", "")
        output_file = f'{output_file_path}.csv'
        df.to_csv(output_file)
        return df
    
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!! For testing only !!!!!!!!!!!!!!!!!!!!!!!
    @staticmethod
    def batch_generate_attack_analysis_csvs(root_dir="results"):
        for model_folder in os.listdir(root_dir):
            model_path = os.path.join(root_dir, model_folder)
            full_test_suite_path = os.path.join(model_path, "full_test_suite")
            
            if os.path.isdir(full_test_suite_path):
                print(f"\nProcessing model: {model_folder}")
                
                json_files = [f for f in os.listdir(full_test_suite_path) if f.endswith('.json')]
                
                if not json_files:
                    print(f"No JSON files found in {full_test_suite_path}")
                    continue
                
                for json_file in json_files:
                    json_path = os.path.join(full_test_suite_path, json_file)
                    try:
                        print(f"Processing: {json_file}")
                        ResultSaver.generate_attack_analysis_excel(json_path)
                        print(f"Successfully generated CSV for {json_file}")
                    except Exception as e:
                        print(f"Failed to process {json_file}: {str(e)}")
            else:
                print(f"No 'full_test_suite' directory found for model: {model_folder}")

        print("\nBatch CSV generation complete!")

class MessageFormatter:
    @staticmethod
    def format_messages(llm_provider: str, system_message: str = None, user_message: str = None, messages: list = None):
        if messages:
            # If messages are already provided, just convert them to the right format
            return MessageFormatter._convert_existing_messages(llm_provider, messages)
        else:
            # Build new messages from system/user content
            return MessageFormatter._build_new_messages(llm_provider, system_message, user_message)
    
    @staticmethod
    def _convert_existing_messages(llm_provider, messages):
        if llm_provider.lower() == 'azure':
            return MessageFormatter._to_azure_format(messages)
        elif llm_provider.lower() == 'aws':
            return MessageFormatter._to_aws_format(messages)
        else:
            raise ValueError(f"Unsupported LLM provider: {llm_provider}")
    
    @staticmethod
    def _build_new_messages(llm_provider, system_message, user_message):
        if llm_provider.lower() == 'azure':
            messages = []
            if system_message:
                messages.append({"role": "system", "content": system_message})
            if user_message:
                messages.append({"role": "user", "content": user_message})
            return messages
            
        elif llm_provider.lower() == 'aws':
            messages = []
            if system_message:
                messages.append({"role": "system", "content": [{"text": system_message}]})
            if user_message:
                messages.append({"role": "user", "content": [{"text": user_message}]})
            return messages
            
        else:
            raise ValueError(f"Unsupported LLM provider: {llm_provider}")
    
    @staticmethod
    def _to_azure_format(messages):
        formatted_messages = []
        for msg in messages:
            if 'content' in msg and isinstance(msg['content'], list):
                role = msg['role']
                content = msg['content'][0]['text'] if msg['content'] else ""
                formatted_messages.append({"role": role, "content": content})
            else:
                formatted_messages.append(msg)
        return formatted_messages
    
    @staticmethod
    def _to_aws_format(messages: list):
        formatted_messages = []
        for msg in messages:
            if msg.get('role') == 'system':
                continue
            if 'content' in msg and not isinstance(msg['content'], list):
                formatted_messages.append({
                    "role": msg['role'],
                    "content": [{"text": msg['content']}]
                })
            else:
                formatted_messages.append(msg)
        return formatted_messages

class ToolFormatter:
    @staticmethod
    def format_tools(llm_provider: str, tools: Union[List[Dict], Dict]) -> Union[List[Dict], Dict]:
        if llm_provider.lower() == 'azure':
            return ToolFormatter._to_azure_format(tools)
        elif llm_provider.lower() == 'aws':
            return ToolFormatter._to_aws_format(tools)
        else:
            raise ValueError(f"Unsupported LLM provider: {llm_provider}")

    @staticmethod
    def _to_azure_format(tools: Union[List[Dict], Dict]) -> List[Dict]:
        if isinstance(tools, dict) and 'tools' in tools:
            return [{
                "type": "function",
                "function": {
                    "name": tool['toolSpec']['name'],
                    "description": tool['toolSpec']['description'],
                    "parameters": tool['toolSpec']['inputSchema']['json'],
                    "strict": True
                }
            } for tool in tools['tools']]
        return tools

    @staticmethod
    def _to_aws_format(tools: Union[List[Dict], Dict]) -> Dict:
        if isinstance(tools, list):
            # Convert from Azure to AWS format
            return {
                "tools": [{
                    "toolSpec": {
                        "name": tool['function']['name'],
                        "description": tool['function']['description'],
                        "inputSchema": {
                            "json": tool['function']['parameters']
                        }
                    }
                } for tool in tools if tool.get('type') == 'function']
            }
        return tools