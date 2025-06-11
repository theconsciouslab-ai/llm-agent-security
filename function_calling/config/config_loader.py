from dataclasses import dataclass
from dotenv import load_dotenv
import os
from typing import List

load_dotenv()

@dataclass
class ExperimentConfig:
    framework_used: str 
    judge_llm: str
    attacker_llm: str


@dataclass
class ModelConfig:
    model_type: str  
    model_provider: str
    moderation_function: str
    safety_level: str
    reasoning_capability: str
            

@dataclass
class AzureConfig(ModelConfig):
    endpoint: str
    api_key: str
    model_name: str
    api_version: str
    sdk_type: str

@dataclass
class AWSConfig(ModelConfig):
    aws_access_key_id: str
    aws_secret_access_key: str
    region_name: str
    model_name: str

class ConfigLoader:
    def __init__(self):
        load_dotenv()
        self._loaded_models = {}

    def load_all_models(self):
        models = {}
        # Load Azure models
        models.update(self._load_azure_models())
        # Load AWS models 
        models.update(self._load_aws_models())
        
        self._loaded_models = models
        return models
    
    def get_model_config(self, model_id: str):
        if not self._loaded_models:
            self.load_all_models()
        if model_id not in self._loaded_models:
            raise ValueError(f"Model {model_id} not found in configuration")
        return self._loaded_models[model_id]
    
    def get_experiment_config(self):
        return ExperimentConfig(
            framework_used = "FC", 
            judge_llm = "deepseek_v3",
            attacker_llm = "azure_gpt_4",
        )
    
    def list_available_models(self) -> List[str]:
        if not self._loaded_models:
            self.load_all_models()
        return list(self._loaded_models.keys())
    
    def _load_azure_models(self):
        azure_models = {}

        azure_defaults = {
            'model_type': 'azure',
            'moderation_function':'Content Filtering',
        }
        
        # GPT O-1
        if os.getenv('AZURE_OPENAI_O1_API_KEY'):
            azure_models['azure_o1'] = AzureConfig(
                api_key=os.getenv('AZURE_OPENAI_O1_API_KEY'),
                endpoint=os.getenv('AZURE_OPENAI_O1_ENDPOINT').replace('\\x3a', ':').rstrip('/'),
                model_name=os.getenv('AZURE_OPENAI_O1_MODEL_NAME'),
                api_version=os.getenv('AZURE_OPENAI_O1_API_VERSION'),
                sdk_type= os.getenv('AZURE_OPENAI_O1_SDK_TYPE'),
                model_provider= os.getenv('AZURE_OPENAI_O1_MODEL_PROVIDER'),
                safety_level= os.getenv('AZURE_OPENAI_O1_SAFETY_LEVEL'),
                reasoning_capability=os.getenv('AZURE_OPENAI_O1_REASONING_CAPABILITY'),
                **azure_defaults
            )
        
        # GPT O-3-mini
        if os.getenv('AZURE_OPENAI_O3_MINI_API_KEY'):
            azure_models['azure_o3_mini'] = AzureConfig(
                api_key=os.getenv('AZURE_OPENAI_O3_MINI_API_KEY'),
                endpoint=os.getenv('AZURE_OPENAI_O3_MINI_ENDPOINT').replace('\\x3a', ':').rstrip('/'),
                model_name=os.getenv('AZURE_OPENAI_O3_MINI_MODEL_NAME'),
                api_version=os.getenv('AZURE_OPENAI_O3_MINI_API_VERSION'),
                sdk_type= os.getenv('AZURE_OPENAI_O3_MINI_SDK_TYPE'),
                model_provider= os.getenv('AZURE_OPENAI_O3_MINI_MODEL_PROVIDER'),
                safety_level= os.getenv('AZURE_OPENAI_O3_MINI_SAFETY_LEVEL'),
                reasoning_capability=os.getenv('AZURE_OPENAI_O3_MINI_REASONING_CAPABILITY'),
                **azure_defaults
            )
        
        # GPT 4.5
        if os.getenv('AZURE_OPENAI_GPT_4_5_API_KEY'):
            azure_models['azure_gpt_4_5'] = AzureConfig(
                api_key=os.getenv('AZURE_OPENAI_GPT_4_5_API_KEY'),
                endpoint=os.getenv('AZURE_OPENAI_GPT_4_5_ENDPOINT').replace('\\x3a', ':').rstrip('/'),
                model_name=os.getenv('AZURE_OPENAI_GPT_4_5_MODEL_NAME'),
                api_version=os.getenv('AZURE_OPENAI_GPT_4_5_API_VERSION'),
                sdk_type= os.getenv('AZURE_OPENAI_GPT_4_5_SDK_TYPE'),
                model_provider= os.getenv('AZURE_OPENAI_GPT_4_5_MODEL_PROVIDER'),
                safety_level= os.getenv('AZURE_OPENAI_GPT_4_5_SAFETY_LEVEL'),
                reasoning_capability=os.getenv('AZURE_OPENAI_GPT_4_5_REASONING_CAPABILITY'),
                **azure_defaults
            )

        # GPT 4.1
        if os.getenv('AZURE_OPENAI_GPT_4_1_API_KEY'):
            azure_models['azure_gpt_4_1'] = AzureConfig(
                api_key=os.getenv('AZURE_OPENAI_GPT_4_1_API_KEY'),
                endpoint=os.getenv('AZURE_OPENAI_GPT_4_1_ENDPOINT').replace('\\x3a', ':').rstrip('/'),
                model_name=os.getenv('AZURE_OPENAI_GPT_4_1_MODEL_NAME'),
                api_version=os.getenv('AZURE_OPENAI_GPT_4_1_API_VERSION'),
                sdk_type= os.getenv('AZURE_OPENAI_GPT_4_1_SDK_TYPE'),
                model_provider= os.getenv('AZURE_OPENAI_GPT_4_1_MODEL_PROVIDER'),
                safety_level= os.getenv('AZURE_OPENAI_GPT_4_1_SAFETY_LEVEL'),
                reasoning_capability=os.getenv('AZURE_OPENAI_GPT_4_1_REASONING_CAPABILITY'),
                **azure_defaults
            )
        
        # GPT 4
        if os.getenv('AZURE_OPENAI_GPT_4_API_KEY'):
            azure_models['azure_gpt_4'] = AzureConfig(
                api_key=os.getenv('AZURE_OPENAI_GPT_4_API_KEY'),
                endpoint=os.getenv('AZURE_OPENAI_GPT_4_ENDPOINT').replace('\\x3a', ':').rstrip('/'),
                model_name=os.getenv('AZURE_OPENAI_GPT_4_MODEL_NAME'),
                api_version=os.getenv('AZURE_OPENAI_GPT_4_API_VERSION'),
                sdk_type= os.getenv('AZURE_OPENAI_GPT_4_SDK_TYPE'),
                model_provider= os.getenv('AZURE_OPENAI_GPT_4_MODEL_PROVIDER'),
                safety_level= os.getenv('AZURE_OPENAI_GPT_4_SAFETY_LEVEL'),
                reasoning_capability=os.getenv('AZURE_OPENAI_GPT_4_REASONING_CAPABILITY'),
                **azure_defaults
            )

        # GPT 35 Turbo
        if os.getenv('AZURE_OPENAI_GPT_35_API_KEY'):
            azure_models['azure_gpt_35_turbo'] = AzureConfig(
                api_key=os.getenv('AZURE_OPENAI_GPT_35_API_KEY'),
                endpoint=os.getenv('AZURE_OPENAI_GPT_35_ENDPOINT').replace('\\x3a', ':').rstrip('/'),
                model_name=os.getenv('AZURE_OPENAI_GPT_35_MODEL_NAME'),
                api_version=os.getenv('AZURE_OPENAI_GPT_35_API_VERSION'),
                sdk_type= os.getenv('AZURE_OPENAI_GPT_35_SDK_TYPE'),
                model_provider= os.getenv('AZURE_OPENAI_GPT_35_MODEL_PROVIDER'),
                safety_level= os.getenv('AZURE_OPENAI_GPT_35_SAFETY_LEVEL'),
                reasoning_capability=os.getenv('AZURE_OPENAI_GPT_35_REASONING_CAPABILITY'),
                **azure_defaults
            )

        # GPT 4o mini
        if os.getenv('AZURE_OPENAI_4O_MINI_API_KEY'):
            azure_models['azure_gpt_4o_mini'] = AzureConfig(
                api_key=os.getenv('AZURE_OPENAI_4O_MINI_API_KEY'),
                endpoint=os.getenv('AZURE_OPENAI_4O_MINI_ENDPOINT').replace('\\x3a', ':').rstrip('/'),
                model_name=os.getenv('AZURE_OPENAI_4O_MINI_MODEL_NAME'),
                api_version=os.getenv('AZURE_OPENAI_4O_MINI_API_VERSION'),
                sdk_type= os.getenv('AZURE_OPENAI_4O_MINI_SDK_TYPE'),
                model_provider= os.getenv('AZURE_OPENAI_4O_MINI_MODEL_PROVIDER'),
                safety_level= os.getenv('AZURE_OPENAI_4O_MINI_SAFETY_LEVEL'),
                reasoning_capability=os.getenv('AZURE_OPENAI_4O_MINI_REASONING_CAPABILITY'),
                **azure_defaults
            )
        
        # DeepSeek-V3
        if os.getenv('AZURE_API_KEY_DeepSeek_V3'):
            azure_models['azure_deepseek_v3'] = AzureConfig(
                api_key=os.getenv('AZURE_API_KEY_DeepSeek_V3'),
                endpoint=os.getenv('AZURE_ENDPOINT_DeepSeek_V3').replace('\\x3a', ':').rstrip('/'),
                model_name=os.getenv('AZURE_MODEL_NAME_DeepSeek_V3'),
                api_version=os.getenv('AZURE_API_VERSION_DeepSeek_V3'),
                sdk_type= os.getenv('AZURE_SDK_TYPE_DeepSeek_V3'),
                model_provider= os.getenv('AZURE_MODEL_PROVIDER_DeepSeek_V3'),
                safety_level= os.getenv('AZURE_SAFETY_LEVEL_DeepSeek_V3'),
                reasoning_capability=os.getenv('AZURE_REASONING_CAPABILITY_DeepSeek_V3'),
                **azure_defaults
            )

        # DeepSeek-R1
        if os.getenv('AZURE_API_KEY_DeepSeek_R1'):
            azure_models['azure_deepseek_r1'] = AzureConfig(
                api_key=os.getenv('AZURE_API_KEY_DeepSeek_R1'),
                endpoint=os.getenv('AZURE_ENDPOINT_DeepSeek_R1').replace('\\x3a', ':').rstrip('/'),
                model_name=os.getenv('AZURE_MODEL_NAME_DeepSeek_R1'),
                api_version=os.getenv('AZURE_API_VERSION_DeepSeek_R1'),
                sdk_type= os.getenv('AZURE_SDK_TYPE_DeepSeek_R1'),
                model_provider= os.getenv('AZURE_MODEL_PROVIDER_DeepSeek_R1'),
                safety_level= os.getenv('AZURE_SAFETY_LEVEL_DeepSeek_R1'),
                reasoning_capability=os.getenv('AZURE_REASONING_CAPABILITY_DeepSeek_R1'),
                **azure_defaults
            )
        
        return azure_models
    
    def _load_aws_models(self):
        aws_models = {}

        aws_defaults = {
            'model_type': 'aws',
            'moderation_function': 'Guardrail',
            'model_provider': 'Anthropic',
            'safety_level': None
        }
        
        # Claude 3-7
        if os.getenv('SECRET_ACESS_KEY_CLAUDE_3_7'):
            aws_models['aws_claude_3_7'] = AWSConfig(
                aws_access_key_id=os.getenv('ACESS_KEY_CLAUDE_3_7'),
                aws_secret_access_key=os.getenv('SECRET_ACESS_KEY_CLAUDE_3_7'),
                region_name=os.getenv('REGION_NAME_CLAUDE_3_7'),
                model_name=os.getenv('MODEL_NAME_CLAUDE_3_7'),
                reasoning_capability= 'True',
                **aws_defaults
            )
        
        # Claude 3-5
        if os.getenv('SECRET_ACESS_KEY_CLAUDE_3_5'):
            aws_models['aws_claude_3_5'] = AWSConfig(
                aws_access_key_id=os.getenv('ACESS_KEY_CLAUDE_3_5'),
                aws_secret_access_key=os.getenv('SECRET_ACESS_KEY_CLAUDE_3_5'),
                region_name=os.getenv('REGION_NAME_CLAUDE_3_5'),
                model_name=os.getenv('MODEL_NAME_CLAUDE_3_5'),
                reasoning_capability= 'False',
                **aws_defaults
            )
        
        # Claude Haiku
        if os.getenv('SECRET_ACESS_KEY_CLAUDE_HAIKU'):
            aws_models['aws_claude_haiku'] = AWSConfig(
                aws_access_key_id=os.getenv('ACESS_KEY_CLAUDE_HAIKU'),
                aws_secret_access_key=os.getenv('SECRET_ACESS_KEY_CLAUDE_HAIKU'),
                region_name=os.getenv('REGION_NAME_CLAUDE_HAIKU'),
                model_name=os.getenv('MODEL_NAME_CLAUDE_HAIKU'),
                reasoning_capability= 'False',
                **aws_defaults
            )

        # Claude Sonnet-4
        if os.getenv('SECRET_ACESS_KEY_CLAUDE_SONNET_4'):
            aws_models['aws_claude_sonnet_4'] = AWSConfig(
                aws_access_key_id=os.getenv('ACESS_KEY_CLAUDE_SONNET_4'),
                aws_secret_access_key=os.getenv('SECRET_ACESS_KEY_CLAUDE_SONNET_4'),
                region_name=os.getenv('REGION_NAME_CLAUDE_SONNET_4'),
                model_name=os.getenv('MODEL_NAME_CLAUDE_SONNET_4'),
                reasoning_capability= 'False',
                **aws_defaults
            )
        
        # Claude Opus-4
        if os.getenv('SECRET_ACESS_KEY_CLAUDE_OPUS_4'):
            aws_models['aws_claude_opus_4'] = AWSConfig(
                aws_access_key_id=os.getenv('ACESS_KEY_CLAUDE_OPUS_4'),
                aws_secret_access_key=os.getenv('SECRET_ACESS_KEY_CLAUDE_OPUS_4'),
                region_name=os.getenv('REGION_NAME_CLAUDE_OPUS_4'),
                model_name=os.getenv('MODEL_NAME_CLAUDE_OPUS_4'),
                reasoning_capability= 'False',
                **aws_defaults
            )

        return aws_models

