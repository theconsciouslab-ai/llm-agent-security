from config.config_loader import ConfigLoader
import asyncio
from typing import Dict, List, Optional, Tuple
from tqdm import tqdm
from copy import deepcopy
import pandas as pd
from datetime import datetime
import json
import os
import glob

from attacks.simple_attacks.prompt_injections.system_prompt_injection import MCPSystemPromptModification
from attacks.simple_attacks.prompt_injections.user_prompt_injection import MCPUserPromptModification
from attacks.simple_attacks.man_in_the_middle.tool_choice_api_interception import MCPToolChoiceMITM
from attacks.simple_attacks.man_in_the_middle.tools_api_interception import MCPToolsMITM
from attacks.simple_attacks.json_injections.function_input_interception import MCPJsonInjectionFunctionArgument
from attacks.simple_attacks.indirect_prompt_injections.ipi_function_response import MCPIpIFunctionResponse
from attacks.simple_attacks.tool_injections.tool_injection import MCPToolInjection
from attacks.simple_attacks.dos_attacks.dos_attack_simulation import MCPDoSAttack

from attacks.composed_attacks.loop_calling.loop_calling_prompt_injection_user import MCPLoopCallingUserLevel
from attacks.composed_attacks.loop_calling.loop_calling_prompt_injection_system import MCPLoopCallingSystemLevel
from attacks.composed_attacks.json_injections.json_prompt_injection import MCPJsonInjectionPromptUser

from attacks.chained_attacks.one_step_chained_attack.prompt_injection import MCPPromptInjectionChain
from attacks.chained_attacks.one_step_chained_attack.llm_injection import MCPLLMInjectionChain
from attacks.chained_attacks.one_step_chained_attack.function_injection import MCPFunctionInjectionChain
from attacks.chained_attacks.one_step_chained_attack.response_injection import MCPResponseInjectionChain
from attacks.chained_attacks.one_step_chained_attack.tool_injection import MCPToolInjectionChain

from attacks.chained_attacks.two_step_chained_attack.prompt_injection import MCPPromptInjectionToTooChain, MCPPromptInjectionToLLMChain, MCPPromptInjectionToFunctionChain, MCPPromptInjectionToResponseChain
from attacks.chained_attacks.two_step_chained_attack.llm_injection import MCPLLMInjectionToFunctionChain, MCPLLMInjectionToResponseChain
from attacks.chained_attacks.two_step_chained_attack.tool_injection import MCPToolInjectionToLLMChain, MCPToolInjectionToFunctionChain, MCPToolInjectionToResponseChain

from attacks.chained_attacks.three_step_chained_attack.prompt_injection import MCPPromptInjectionToToolToLLMChain, MCPPromptInjectionToToolToFunctionChain, MCPPromptInjectionToToolToResponseChain, MCPPromptInjectionToLLMToFunctionChain, MCPPromptInjectionToLLMToResponseChain, MCPPromptInjectionToFunctionToResponseChain
from attacks.chained_attacks.three_step_chained_attack.tool_injection import MCPToolInjectionToLLMToFunctionChain, MCPToolInjectionToLLMToResponseChain, MCPToolInjectionToFunctionToResponseChain
from attacks.chained_attacks.three_step_chained_attack.llm_injection import MCPLLMInjectionToFunctionToResponseChain

from attacks.chained_attacks.four_step_chained_attack.prompt_injections import MCPPromptInjectionToToolToLLMToFunctionChain, MCPPromptInjectionToToolToLLMToResponseChain, MCPPromptInjectionToToolToFunctionToResponseChain,MCPPromptInjectionToLLMToFunctionToResponseChain
from attacks.chained_attacks.four_step_chained_attack.tool_injections import MCPToolInjectionToLLMToFunctionToResponseChain

from attacks.chained_attacks.five_step_chained_attack.prompt_injections import MCPPromptInjectionToToolToLLMToFunctionToResponseChain

from mcp_client.client import MCPClient
from metrics.llm_judge import LLM_Judge
from attacks import ServerManager
from __init__ import ResultSaver

class AttackRegistry:
    def __init__(self):
        self.registry = {
            "simple_attacks": {
                "system_prompt_injection": MCPSystemPromptModification,
                "user_prompt_injection": MCPUserPromptModification,
                
            },
            "composed_attacks": {
                "loop_calling_system_level": MCPLoopCallingSystemLevel,
                
            },
            
            
        }
    
    def get_attack(self, category: str, attack_type: str):
        category_attacks = self.registry.get(category.lower())
        if not category_attacks:
            return None
        return category_attacks.get(attack_type.lower())
    
    def register_attack(self, category: str, attack_type: str, attack_class):
        if category.lower() not in self.registry:
            self.registry[category.lower()] = {}
        self.registry[category.lower()][attack_type.lower()] = attack_class

class AttackExecutor:
    def __init__(self):
        self.attack_registry = AttackRegistry()
        
    async def execute_attack(self, attack_category: str, attack_type: str, *args, **kwargs) -> Dict:
        attack_class = self.attack_registry.get_attack(attack_category, attack_type)
        if not attack_class:
            raise ValueError(f"Unknown attack type: {attack_category}/{attack_type}")
            
        attack_instance = attack_class(name=attack_type, description="LLM Attack", **kwargs)
        return await attack_instance.execute(*args)

class TestRunner:
    def __init__(self, config_loader: ConfigLoader):
        self.config_loader = config_loader
        self.attack_executor = AttackExecutor()
        self.llm_judge = self._initialize_llm_judge()
        self.server_manager = ServerManager()

    def _initialize_llm_judge(self) -> LLM_Judge:
        judge_model_id = "azure_deepseek_v3"
        judge_config = self.config_loader.get_model_config(judge_model_id)
        return LLM_Judge(
            api_key=judge_config.api_key,
            endpoint=judge_config.endpoint,
            api_version=judge_config.api_version,
            model_name=judge_config.model_name,
            sdk_type=judge_config.sdk_type
        )
    
    async def _run_single_test(self, model_name: str, category: str, attack_type: str, initial_messages: list) -> Tuple[str, Dict, str, str]:
        client = MCPClient(model_name, self.config_loader)
        try:
            if not await self.server_manager.connect(client, attack_type):
                return None, {"error": "Failed to connect to server"}, category, attack_type
            
            test_results = await self.attack_executor.execute_attack(
                category,
                attack_type,
                client,
                initial_messages,
                self.llm_judge
            )
            
            result_file = ResultSaver.save_test_results(
                model_name,
                category,
                attack_type,
                test_results
            )
            return result_file, test_results, category, attack_type
        except Exception as e:
            error_result = {"error": str(e)}
            result_file = ResultSaver.save_test_results(
                model_name,
                category,
                attack_type,
                error_result
            )
            return result_file, error_result, category, attack_type
        finally:
            await client.cleanup()

    async def run_all_tests(self, model_name: str, initial_messages: list) -> str:
        test_cases = []
        for category, attacks in self.attack_executor.attack_registry.registry.items():
            for attack_type in attacks.keys():
                test_cases.append((model_name, category, attack_type, deepcopy(initial_messages)))
        return await self._execute_test_cases(test_cases, model_name, "full_test_suite", "all_attacks")

    async def run_selected_tests(self, model_name: str, initial_messages: list, 
                               categories: List[str] = None, attack_types: List[str] = None) -> str:
        if categories is None:
            categories = list(self.attack_executor.attack_registry.registry.keys())
        
        test_cases = []
        for category in categories:
            if category not in self.attack_executor.attack_registry.registry:
                continue
                
            for attack_type in self.attack_executor.attack_registry.registry[category]:
                if attack_types and attack_type not in attack_types:
                    continue
                
                test_cases.append((model_name, category, attack_type, deepcopy(initial_messages)))
        
        return await self._execute_test_cases(test_cases, model_name, "selected_test_suite", "selected_attacks")

    async def _execute_test_cases(self, test_cases: list, model_name: str, suite_type: str, suite_name: str) -> str:
        total_tests_attacks = len(test_cases)
        results = {}
        raw_results = []
        total_tests = 0
        
        with tqdm(total=total_tests_attacks, desc="Running test suite") as pbar:
            for test_case in test_cases:
                result_file, test_result, category, attack_type = await self._run_single_test(*test_case)
                if result_file:  # Only process if we got a result
                    if category not in results:
                        results[category] = {}
                    results[category][attack_type] = test_result
                    total_tests = total_tests + len(test_result['detailed_results'])
                    raw_results.append(test_result)
                pbar.update(1)
        
        # Save comprehensive results
        summary_file = ResultSaver.save_test_results(
            model_name,
            suite_type,
            suite_name,
            {
                "results": results,
                "stats": self._generate_stats(results)
            }
        )
        df = ResultSaver.generate_attack_analysis_excel(summary_file)
        
        # Save overall success and refusal rates
        self._save_model_summary(model_name, summary_file, total_tests)
        
        return summary_file

    def _generate_stats(self, results: dict) -> dict:
        stats = {
            "total_tests": 0,
            "successful": 0,
            "failed": 0,
            "success_rate_total": 0.0,
            "refusal_rate_total": 0.0,
            "by_category": {}
        }

        total_successful_attacks = 0
        total_refusals = 0
        total_test_cases = 0

        for category, attacks in results.items():
            category_stats = {
                "total": 0,
                "successful": 0,
                "failed": 0,
                "success_rate": 0.0,
                "refusal_rate": 0.0,
                "test_cases": 0,
                "successful_attacks": 0,
                "successful_refusals": 0
            }

            for attack_type, attack_result in attacks.items():
                if "error" in attack_result:
                    category_stats["failed"] += 1
                    continue

                category_stats["successful"] += 1
                detailed_results = attack_result.get("detailed_results", {})

                if not isinstance(detailed_results, dict):
                    continue

                test_cases = len(detailed_results)
                category_stats["test_cases"] += test_cases
                total_test_cases += test_cases

                for case_id, case in detailed_results.items():
                    if case.get("attack_success", False):
                        category_stats["successful_attacks"] += 1
                        total_successful_attacks += 1
                    if case.get("refusal_success", False):
                        category_stats["successful_refusals"] += 1
                        total_refusals += 1

            if category_stats["test_cases"] > 0:
                category_stats["success_rate"] = (category_stats["successful_attacks"] / category_stats["test_cases"]) * 100
                category_stats["refusal_rate"] = (category_stats["successful_refusals"] / category_stats["test_cases"]) * 100

            stats["by_category"][category] = {
                "total": category_stats["total"],
                "successful": category_stats["successful"],
                "failed": category_stats["failed"],
                "success_rate": category_stats["success_rate"],
                "refusal_rate": category_stats["refusal_rate"]
            }

            stats["total_tests"] += category_stats["total"]
            stats["successful"] += category_stats["successful"]
            stats["failed"] += category_stats["failed"]

        if total_test_cases > 0:
            stats["success_rate_total"] = (total_successful_attacks / total_test_cases) * 100
            stats["refusal_rate_total"] = (total_refusals / total_test_cases) * 100

        return stats
    
    def _save_model_summary(self, model_name: str, json_file_path: str, total_test_cases:int) -> None:
        
        with open(json_file_path, 'r') as f:
            data = json.load(f)
        
        model_summary = {
            "model_name": model_name,
            "total_tests": total_test_cases,
            "overall_success_rate": data["results"]["stats"]["success_rate_total"],
            "overall_refusal_rate": data["results"]["stats"]["refusal_rate_total"],
            "categories": data["results"]["stats"]["by_category"],
            "timestamp": f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        }

        model_folder = os.path.join("results", model_name)
        os.makedirs(model_folder, exist_ok=True)
        
        summary_path = os.path.join(model_folder, f"{model_name}_summary.json")
        with open(summary_path, 'w') as f:
            json.dump(model_summary, f, indent=4)
    
    def concatenate_test_suite_csvs(self, output_file: str = "final_results.csv"):
        df_list = []
        root_dir = "results"
        print(f"output_file type: {type(output_file)}, value: {output_file}")

        for model_folder in os.listdir(root_dir):
            model_path = os.path.join(root_dir, model_folder, "full_test_suite")
            
            if os.path.isdir(model_path):
                csv_files = glob.glob(os.path.join(model_path, "*.csv"))
                
                if csv_files:
                    for file in csv_files:
                        try:
                            df = pd.read_csv(file)
                            df_list.append(df)
                        except Exception as e:
                            print(f"Error reading {file}: {e}")
                else:
                    print(f"No CSV files in: {model_path}")
            else:
                print(f"'full_test_suite' not found in: {os.path.join(root_dir, model_folder)}")
        
        final_path = os.path.join(root_dir, f"{output_file}")
        if df_list:
            combined_df = pd.concat(df_list, ignore_index=True)
            combined_df.to_csv(final_path, index=False)
            print(f"Final CSV saved to: {final_path}")
        else:
            print("No valid CSV files found.")


async def main():
    config_loader = ConfigLoader()
    runner = TestRunner(config_loader)
    initial_messages = [
        {"role": "system", "content": "You are a helpful assistant."},
    ]
    
    test_config = {
        "model_name": "azure_gpt_4_1",
        "initial_messages": initial_messages,
        "categories": None,  
        "attack_types": None  
    }
    
    if test_config["categories"] or test_config["attack_types"]:
        summary_file = await runner.run_selected_tests(
            model_name=test_config["model_name"],
        )
    else:
        summary_file = await runner.run_all_tests(
            model_name=test_config["model_name"],
            initial_messages=initial_messages
        )
    runner.concatenate_test_suite_csvs()
    print(f"\nTest execution complete. Results saved to: {summary_file}")


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(main())
    finally:
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
            
        try:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception as e:
            print(f"Error during shutdown: {e}")
        finally:
            loop.close()
