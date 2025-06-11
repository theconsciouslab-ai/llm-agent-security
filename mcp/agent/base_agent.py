from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

class BaseAgent(ABC):        
    @abstractmethod
    async def run_conversation(self, 
                             messages: List[Dict[str, Any]],
                             session: Optional[Any] = None,
                             timeout: float = 30) -> Dict[str, Any]:
        pass