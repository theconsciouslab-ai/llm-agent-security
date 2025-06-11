import asyncio
from config.config_loader import ConfigLoader
from __init__ import ResultSaver

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

class AttackRegistry:
    def __init__(self):
        self.registry = {
            "simple_attacks": {
                "system_prompt_injection": MCPSystemPromptModification,
                "user_prompt_injection": MCPUserPromptModification,
                "user_prompt_injection_instruction_bypass": lambda **kwargs: MCPUserPromptModification(scenario_file="./tests/test_simple/test_user_prompt_instruction_bypass.json",**kwargs),
                "tool_choice_interception": MCPToolChoiceMITM,
                "tools_interception": MCPToolsMITM,
                "json_injection_function_arguments": MCPJsonInjectionFunctionArgument,
                "indirect_prompt_injection": MCPIpIFunctionResponse,
                "tool_injection": MCPToolInjection,
                "dos_attack": MCPDoSAttack
            },
            "composed_attacks": {
                "loop_calling_system_level": MCPLoopCallingSystemLevel,
                "loop_calling_user_level": MCPLoopCallingUserLevel,
                "loop_calling_user_level_instruction_based": lambda **kwargs: MCPLoopCallingUserLevel(scenario_file="./tests/test_composed/test_loop_calling_instruction_based.json",**kwargs),
                "json_prompt_injection_user_level": MCPJsonInjectionPromptUser,
                "json_prompt_injection_user_level_instruction_based": lambda **kwargs: MCPJsonInjectionPromptUser(scenario_file="./tests/test_composed/test_json_prompt_injection_instruction_based_scenarios.json",**kwargs)
            },
            "chained_attacks": {
                "one_step_prompt_injection": MCPPromptInjectionChain,
                "one_step_llm_injection": MCPLLMInjectionChain,
                "one_step_function_injection": MCPFunctionInjectionChain,
                "one_step_response_injection": MCPResponseInjectionChain,
                "one_step_tool_injection": MCPToolInjectionChain,

                "two_step_prompt_tool_chain": MCPPromptInjectionToTooChain,
                "two_step_prompt_llm_chain": MCPPromptInjectionToLLMChain,
                "two_step_prompt_function_chain": MCPPromptInjectionToFunctionChain,
                "two_step_prompt_response_chain": MCPPromptInjectionToResponseChain,
                
                "two_step_tool_llm_chain": MCPToolInjectionToLLMChain,
                "two_step_tool_function_chain": MCPToolInjectionToFunctionChain,
                "two_step_tool_response_chain": MCPToolInjectionToResponseChain,

                "two_step_llm_function_chain": MCPLLMInjectionToFunctionChain,
                "two_step_llm_response_chain": MCPLLMInjectionToResponseChain,

                "three_step_prompt_tool_llm": MCPPromptInjectionToToolToLLMChain,
                "three_step_prompt_tool_function": MCPPromptInjectionToToolToFunctionChain,
                "three_step_prompt_llm_function": MCPPromptInjectionToLLMToFunctionChain,
                "three_step_prompt_llm_response": MCPPromptInjectionToLLMToResponseChain,
                "three_step_prompt_function_response": MCPPromptInjectionToFunctionToResponseChain,

                "three_step_tool_llm_function": MCPToolInjectionToLLMToFunctionChain,
                "three_step_tool_llm_response": MCPToolInjectionToLLMToResponseChain,
                "three_step_tool_function_response": MCPToolInjectionToFunctionToResponseChain,

                "three_step_llm_function_response": MCPLLMInjectionToFunctionToResponseChain,

                "four_step_prompt_tool_llm_function": MCPPromptInjectionToToolToLLMToFunctionChain,
                "four_step_prompt_tool_llm_response": MCPPromptInjectionToToolToLLMToResponseChain,
                "four_step_prompt_tool_function_response": MCPPromptInjectionToToolToFunctionToResponseChain,
                "four_step_prompt_llm_function_response": MCPPromptInjectionToLLMToFunctionToResponseChain,
                
                "four_step_tool_llm_function_response": MCPToolInjectionToLLMToFunctionToResponseChain,
                
                "five_step_prompt_tool_llm_function_response": MCPPromptInjectionToToolToLLMToFunctionToResponseChain
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
        
    async def execute_attack(self, attack_category, attack_type, *args, **kwargs):
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
        
    async def run_test(self, model_name: str, attack_category: str, attack_type: str, initial_messages: list):
        server_manager = ServerManager()
        client = MCPClient(model_name, self.config_loader)
        try:
            if not await server_manager.connect(client, attack_type):
                return

            # Execute attack
            test_results = await self.attack_executor.execute_attack(
                attack_category, 
                attack_type, 
                client,
                initial_messages,
                self.llm_judge
            )
            
            # Save results
            return ResultSaver.save_test_results(
                model_name,
                attack_category,
                attack_type,
                test_results
            )
        finally:
            await client.cleanup()

        
        

async def main():
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
    results_file = await runner.run_test(**test_config)
    print(f"Test completed. Results saved to: {results_file}")
    
    
if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        print("Starting MCP Client...")
        loop.run_until_complete(main())
    finally:
        # Properly shut down the event loop
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
            
        try:
            # Wait for tasks to acknowledge cancellation (with timeout)
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception as e:
            print(f"Error during shutdown: {e}")
        finally:
            loop.close()