from openai import AzureOpenAI
from azure.ai.inference import ChatCompletionsClient
from azure.core.credentials import AzureKeyCredential

class Azure_models:
    def __init__(self, api_key, endpoint, api_version, sdk_type):
       
        self.api_key = api_key
        self.endpoint = endpoint
        self.api_version = api_version
        self.sdk_type = sdk_type
    

    # Client Initialization of Models using Azure OpenAI SDK
    def create_azure_openai_client(self):
        return AzureOpenAI(
            api_key=self.api_key,
            api_version=self.api_version,
            azure_endpoint=self.endpoint
        )
    
    # Client initialization of Models using Azure Ai Inference
    def create_azure_ai_inference(self):
        return ChatCompletionsClient(
            endpoint=self.endpoint,
            credential=AzureKeyCredential(self.api_key),
            api_version=self.api_version
        )
    
    # Client initialization based on SDK type
    def create_azure_client(self):
        if self.sdk_type == 'azure_openai_sdk':
            return self.create_azure_openai_client()
        else:
            return self.create_azure_ai_inference()