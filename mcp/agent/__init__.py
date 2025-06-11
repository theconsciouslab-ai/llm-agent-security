from agent.aws_agent import AwsAgent
from agent.azure_agent import Agent
from config.config_loader import ConfigLoader

class AgentFactory:
    @staticmethod
    def create_agent(model_id: str, config_loader: ConfigLoader = None):
        if not config_loader:
            config_loader = ConfigLoader()
            
        config = config_loader.get_model_config(model_id)
        
        if config.model_type == "azure":
            return (
                Agent(
                    api_key=config.api_key,
                    endpoint=config.endpoint,
                    api_version=config.api_version,
                    model_name=config.model_name
                ),
                config.model_type
            )
        elif config.model_type == "aws":
            return (
                AwsAgent(
                    aws_access_key_id=config.aws_access_key_id,
                    aws_secret_access_key=config.aws_secret_access_key,
                    region_name=config.region_name,
                    model_name=config.model_name
                ),
                config.model_type
            )
        else:
            raise ValueError(f"Unsupported model type: {config.model_type}")

