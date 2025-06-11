import boto3
import json

class AWSModels:
    def __init__(self, aws_access_key_id, aws_secret_access_key, region_name, service_name='bedrock-runtime'):
       
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.region_name = region_name
        self.service_name = service_name
    

    # Client Initialization of Models using Azure OpenAI SDK
    def create_aws_client(self):
        return boto3.client(
            service_name=self.service_name,
            region_name= self.region_name,
            aws_access_key_id= self.aws_access_key_id,
            aws_secret_access_key= self.aws_secret_access_key
        )