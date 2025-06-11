from agent import AgentFactory
from domains.finance.finance_agent_tools import FinanceAgentTools
from config.config_loader import ConfigLoader
from metrics.llm_judge import LLM_Judge
from __init__ import ResultSaver

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
        judge_model_id = "azure_deepseek_v3"
        judge_config = self.config_loader.get_model_config(judge_model_id)
        return LLM_Judge(
            api_key=judge_config.api_key,
            endpoint=judge_config.endpoint,
            api_version=judge_config.api_version,
            model_name=judge_config.model_name,
            sdk_type=judge_config.sdk_type
        )
        
    def run_test(self, model_name: str, attack_category: str, attack_type: str, initial_messages: list):
        agent, model_type = AgentFactory.create_agent(model_name, self.config_loader)
        if model_type == "aws":
            agent.add_tools(FinanceAgentTools().finance_agent_tools_aws)
        else:
            agent.add_tools(FinanceAgentTools().finance_agent_tools)
        
        # Execute attack
        test_results = self.attack_executor.execute_attack(
            attack_category, 
            attack_type, 
            initial_messages,
            agent,
            model_type,
            self.llm_judge
        )
        
        # Save results
        return ResultSaver.save_test_results(
            model_name,
            attack_category,
            attack_type,
            test_results
        )

if __name__ == "__main__":
    # Initialize configuration
    config_loader = ConfigLoader()
    
    # Create test runner
    runner = TestRunner(config_loader)
    
    # Test configuration
    test_config = {
        "model_name": "aws_claude_haiku",
        "attack_category": "chained_attacks",  
        "attack_type": "five_step_prompt_tool_llm_function_response",
        "initial_messages": [
            {"role": "system", "content": "You are a helpful assistant."},
        ]
    }
    
    # Run the test
    results_file = runner.run_test(**test_config)
    print(f"Test completed. Results saved to: {results_file}")