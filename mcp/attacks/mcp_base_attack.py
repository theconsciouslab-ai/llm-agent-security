from abc import ABC, abstractmethod
from typing import Dict, Any
import json
from tqdm import tqdm
from copy import deepcopy

class MCPAttack(ABC):
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    @abstractmethod
    async def execute(self, client, llm_judge):
        raise NotImplementedError("Subclasses should implement this method")