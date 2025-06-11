from agent import AgentFactory
from domains.finance.finance_agent_tools import FinanceAgentTools
from config.config_loader import ConfigLoader
from metrics.llm_judge import LLM_Judge
from __init__ import ResultSaver
from typing import Dict, List
from tqdm import tqdm
from copy import deepcopy
from datetime import datetime
import json
import os
import pandas as pd
import glob

from attacks.simple_attacks.prompt_injections.system_prompt_modification import SystemPromptModification
from attacks.simple_attacks.prompt_injections.user_prompt_modification import UserInputModification
from attacks.simple_attacks.man_in_the_middle.api_interception import InterceptionOfAPI
from attacks.simple_attacks.man_in_the_middle.tool_injection_api_interception import ToolInjectionInterceptionAPI
from attacks.simple_attacks.json_injections.json_injection_function_arguments import JSONInjectionFunctionArguments
from attacks.simple_attacks.json_injections.function_output_corruption import FunctionOutputInjector
from attacks.simple_attacks.tool_injections.tool_injection import ToolInjection
from attacks.simple_attacks.indirect_prompt_injections.ipi_function_response import IndirectPromptInjection

from attacks.composed_attacks.loop_calling.loop_calling_prompt_injection_at_system_level import LoopCallingFunctionAtSystemLevel
from attacks.composed_attacks.loop_calling.loop_calling_prompt_injection_at_user_level import LoopCallingFunctionAtUserLevel
from attacks.composed_attacks.json_injections.json_prompt_injection import JSONPromptInjectionAtUserLevel

from attacks.chained_attacks.one_step_chained_attack.prompt_injection import PromptInjectionChain
from attacks.chained_attacks.one_step_chained_attack.llm_function_injection import LLMFunctionInjectionChain
from attacks.chained_attacks.one_step_chained_attack.function_injection import FunctionInjectionChain
from attacks.chained_attacks.one_step_chained_attack.response_injection import ResponseInjectionChain
from attacks.chained_attacks.one_step_chained_attack.tool_injection import ToolInjectionChain

from attacks.chained_attacks.two_step_chained_attack.prompt_injection import PromptInjectionToToolChain, PromptInjectionToLLMChain, PromptInjectionToFunctionChain, PromptInjectionToResponseChain
from attacks.chained_attacks.two_step_chained_attack.tool_injection import ToolInjectionToLLMChain, ToolInjectionToFunctionChain, ToolInjectionToResponseChain
from attacks.chained_attacks.two_step_chained_attack.llm_function import LLMInjectionToFunctionChain, LLMInjectionToResponseChain

from attacks.chained_attacks.three_step_chained_attack.prompt_injection import PromptInjectionToTooltoLLMChain, PromptInjectionToTooltoFunctionChain, PromptInjectionToLLMToFunctionChain,PromptInjectionToLLMToResponseChain, PromptInjectionToFunctionToResponseChain
from attacks.chained_attacks.three_step_chained_attack.tool_injection import ToolToLLMToFunctionChain, ToolToLLMToResponseChain, ToolToFunctionToResponseChain
from attacks.chained_attacks.three_step_chained_attack.llm_function_injection import LLMToFunctionToResponseChain

from attacks.chained_attacks.four_step_chained_attack.prompt_injection import PromptToTooltoLLMtoFunctionChain, PromptToTooltoFunctionToResponseChain, PromptToLLMToFunctionToResponseChain
from attacks.chained_attacks.four_step_chained_attack.tool_injection import ToolToLLMToFunctionToResponseChain

from attacks.chained_attacks.five_step_chained_attack.prompt_injection import PromptToToolToLLMToFunctionToResponseChain

class AttackRegistry:
    def __init__(self):
        self.registry = {
            "simple_attacks": {
                "system_prompt_injection": SystemPromptModification,
                "user_prompt_injection": UserInputModification,
                "tool_choice_intereception":InterceptionOfAPI,
                "tools_interception":ToolInjectionInterceptionAPI,
                "json_injection_function_arguments":JSONInjectionFunctionArguments,
                "json_injection_function_output":FunctionOutputInjector,
                "tool_injection":ToolInjection,
                "indirect_prompt_injection":IndirectPromptInjection
            },
            "composed_attacks": {
                "loop_calling_system_level":LoopCallingFunctionAtSystemLevel,
                "loop_calling_user_level":LoopCallingFunctionAtUserLevel,
                "json_prompt_injection_user_level":JSONPromptInjectionAtUserLevel
            },
            "chained_attacks": {
                "one_step_prompt_injection":PromptInjectionChain,
                "one_step_llm_injection":LLMFunctionInjectionChain,
                "one_step_function_injection":FunctionInjectionChain,
                "one_step_response_injection":ResponseInjectionChain,
                "one_step_tool_injection": ToolInjectionChain,

                "two_step_prompt_tool_chain":PromptInjectionToToolChain,
                "two_step_prompt_llm_chain":PromptInjectionToLLMChain,
                "two_step_prompt_function_chain":PromptInjectionToFunctionChain,
                "two_step_prompt_response_chain":PromptInjectionToResponseChain,
                
                "two_step_tool_llm_chain":ToolInjectionToLLMChain,
                "two_step_tool_function_chain":ToolInjectionToFunctionChain,
                "two_step_tool_response_chain": ToolInjectionToResponseChain,

                "two_step_llm_function_chain":LLMInjectionToFunctionChain,
                "two_step_llm_response_chain":LLMInjectionToResponseChain,

                "three_step_prompt_tool_llm":PromptInjectionToTooltoLLMChain,
                "three_step_prompt_tool_function":PromptInjectionToTooltoFunctionChain,
                "three_step_prompt_llm_function":PromptInjectionToLLMToFunctionChain,
                "three_step_prompt_llm_response":PromptInjectionToLLMToResponseChain,
                "three_step_prompt_function_response":PromptInjectionToFunctionToResponseChain,

                "three_step_tool_llm_function":ToolToLLMToFunctionChain,
                "three_step_tool_llm_response":ToolToLLMToResponseChain,
                "three_step_tool_function_response":ToolToFunctionToResponseChain,

                "three_step_llm_function_response": LLMToFunctionToResponseChain,

                "four_step_prompt_tool_llm_function":PromptToTooltoLLMtoFunctionChain,
                "four_step_prompt_tool_function_response":PromptToTooltoFunctionToResponseChain,
                "four_step_prompt_llm_function_response":PromptToLLMToFunctionToResponseChain,
                "four_step_tool_llm_function_response":ToolToLLMToFunctionToResponseChain,
                
                "five_step_prompt_tool_llm_function_response":PromptToToolToLLMToFunctionToResponseChain
            }
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
        
    def execute_attack(self, attack_category, attack_type, *args, **kwargs):
        attack_class = self.attack_registry.get_attack(attack_category, attack_type)
        if not attack_class:
            raise ValueError(f"Unknown attack type: {attack_category}/{attack_type}")
            
        attack_instance = attack_class(name=attack_type, description="LLM Attack", **kwargs)
        return attack_instance.execute(*args)
    

class TestRunner:
    def __init__(self, config_loader: ConfigLoader):
        self.config_loader = config_loader
        self.attack_executor = AttackExecutor()
        self.llm_judge = self._initialize_llm_judge()
        
    def _initialize_llm_judge(self) -> LLM_Judge:
        judge_model_id = "azure_gpt_35_turbo"
        judge_config = self.config_loader.get_model_config(judge_model_id)
        return LLM_Judge(
            api_key=judge_config.api_key,
            endpoint=judge_config.endpoint,
            api_version=judge_config.api_version,
            model_name=judge_config.model_name,
            sdk_type=judge_config.sdk_type
        )
    
    def _run_single_test(self, model_name: str, category: str, attack_type: str, initial_messages: list):
        try:
            agent, model_type = AgentFactory.create_agent(model_name, self.config_loader)
            
            if model_type == "aws":
                agent.add_tools(FinanceAgentTools().finance_agent_tools_aws)
            else:
                agent.add_tools(FinanceAgentTools().finance_agent_tools)
            
            test_results = self.attack_executor.execute_attack(
                category,
                attack_type,
                initial_messages,
                agent,
                model_type,
                self.llm_judge
            )
            
            return ResultSaver.save_test_results(
                model_name,
                category,
                attack_type,
                test_results
            ), test_results, category, attack_type
        except Exception as e:
            error_result = {
                "error": str(e),
            }
            return ResultSaver.save_test_results(
                model_name,
                category,
                attack_type,
                error_result
            ), error_result
    
    def run_all_tests(self, model_name: str, initial_messages: list):
        test_cases = []
        for category, attacks in self.attack_executor.attack_registry.registry.items():
            for attack_type in attacks.keys():
                test_cases.append((model_name, category, attack_type, deepcopy(initial_messages)))
        
        total_tests_attacks = len(test_cases)
        results = {}
        raw_results = []
        total_tests = 0
        
        with tqdm(total=total_tests_attacks, desc="Running test suite") as pbar:
            for test_case in test_cases:
                summary_file, test_result, category,attack_type = self._run_single_test(*test_case)
                if category not in results:
                    results[category] = {}
                results[category][attack_type] = test_result
                total_tests = total_tests + len(test_result['detailed_results'])
                raw_results.append(test_result)
                pbar.update(1)
        
        # Save comprehensive results
        summary_file = ResultSaver.save_test_results(
            model_name,
            "full_test_suite",
            "all_attacks",
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

        print("==> Starting _generate_stats function...")
        print(f"Input results keys (categories): {list(results.keys())}\n")

        for category, attacks in results.items():
            print(f"\nProcessing category: '{category}'")
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
                print(f"  - Attack type: {attack_type}")
                
                if "error" in attack_result:
                    category_stats["failed"] += 1
                    print(f"    * Skipped due to error. Failed count: {category_stats['failed']}")
                    continue

                category_stats["successful"] += 1
                print(f"    * Processed successfully. Successful count: {category_stats['successful']}")

                detailed_results = attack_result.get("detailed_results", {})
                print("detailed_results:",detailed_results)
    
                if not isinstance(detailed_results, dict):
                    print(f"    ⚠️ Warning: 'detailed_results' not found or invalid in attack_type '{attack_type}'")
                    continue

                test_cases = len(detailed_results)
                print(f"    * Found {test_cases} test case(s)")
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

            print(f"  >> Finished category '{category}'")
            print(f"     Success rate: {category_stats['success_rate']:.2f}%")
            print(f"     Refusal rate: {category_stats['refusal_rate']:.2f}%")
            print(f"     Successful: {category_stats['successful']}, Failed: {category_stats['failed']}\n")

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

        print("\n==> Final stats:")
        print(f"Total test cases: {total_test_cases}")
        print(f"Total successful attacks: {total_successful_attacks}")
        print(f"Total refusals: {total_refusals}")
        print(f"Global success rate: {stats['success_rate_total']:.2f}%")
        print(f"Global refusal rate: {stats['refusal_rate_total']:.2f}%\n")

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

    def run_selected_tests(self, model_name: str, initial_messages: list, 
                         categories: List[str] = None, attack_types: List[str] = None):
        if categories is None:
            categories = list(self.attack_executor.attack_registry.registry.keys())
        if attack_types is None:
            attack_types = []
        
        test_cases = []
        for category in categories:
            if category not in self.attack_executor.attack_registry.registry:
                continue
                
            for attack_type in self.attack_executor.attack_registry.registry[category]:
                if attack_types and attack_type not in attack_types:
                    continue
                
                test_cases.append((model_name, category, attack_type, deepcopy(initial_messages)))
        
        return self._execute_test_cases(test_cases, model_name)

    def _execute_test_cases(self, test_cases: list, model_name: str):
        total_tests = len(test_cases)
        results = {}
        raw_results = []
        
        with tqdm(total=total_tests, desc="Running test suite") as pbar:
            for test_case in test_cases:
                summary_file, test_result, category,attack_type = self._run_single_test(*test_case)                
                if category not in results:
                    results[category] = {}
                results[category][attack_type] = test_result
                raw_results.append(test_result)
                pbar.update(1)
        
        # Save comprehensive results
        summary_file = ResultSaver.save_test_results(
            model_name,
            "selected_test_suite",
            "selected_attacks",
            {
                "results": results,
                "stats": self._generate_stats(results)
            }
        )
        
        # Save overall success and refusal rates in the model folder
        self._save_model_summary(model_name, raw_results)
        
        return summary_file


if __name__ == "__main__":

    config_loader = ConfigLoader()
    runner = TestRunner(config_loader)
    initial_messages = [
        {"role": "system", "content": "You are a helpful assistant."},
    ]
    
    # Configuration options
    test_config = {
        "model_name": "azure_gpt_4",
        "initial_messages": initial_messages,
        "categories": None,
        "attack_types": None
    }
    
    if test_config["categories"] or test_config["attack_types"]:
        summary_file = runner.run_selected_tests(
            model_name=test_config["model_name"],
        )
    else:
        summary_file = runner.run_all_tests(
            model_name=test_config["model_name"],
            initial_messages=initial_messages
        )
    
    runner.concatenate_test_suite_csvs()
    print(f"\nTest execution complete. Results saved to: {summary_file}")

    