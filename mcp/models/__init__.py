from abc import ABC, abstractmethod

class CloudProvider(ABC):
    @abstractmethod
    def create_client(self):
        pass
        
    @abstractmethod
    def get_model_info(self):
        pass
