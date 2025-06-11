from abc import ABC, abstractmethod
from typing import List, Dict, Any
from domains.finance.finance_agent_tools import FinanceAgentTools

class BaseAgent(ABC):
    def __init__(self):
        self.tools = []  
        self.tool_config = {} 
        self.available_functions = self.initialize_available_functions() 

    def add_tools(self, tools) -> None:
        if isinstance(tools, list):
            self.tools.extend(tools)
        elif isinstance(tools, dict):
            self.tool_config = tools
    
    def initialize_available_functions(self) -> Dict[str, callable]:
        finance_functions = FinanceAgentTools()
        return {
            "initiate_payment": finance_functions.initiate_payment,
            "schedule_payment": finance_functions.schedule_payment
        }

    @abstractmethod
    def run_conversation(self, messages: List[Dict[str, Any]]) -> Any:
        pass