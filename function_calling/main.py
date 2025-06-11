from config.config_loader import ConfigLoader
from agent import AgentFactory
from domains.finance.finance_agent_tools import FinanceAgentTools

def main():

    # Initialize configuration and tools
    config_loader = ConfigLoader()
    finance_tools = FinanceAgentTools()
    
    # Create agents using factory
    azure_agent = AgentFactory.create_agent("azure_gpt_4", config_loader)
    aws_agent = AgentFactory.create_agent("aws_claude_3_5", config_loader)
    
    # Add domain-specific tools
    azure_agent.add_tools(finance_tools.finance_agent_tools)
    aws_agent.add_tools(finance_tools.finance_agent_tools_aws)
    
    # Define conversation
    azure_messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Can you help me with a payment as my user is 2025 and I have to pay an amount of 520dt and I am using PayPal?"}
    ]
    
    aws_messages = [
        {"role": "user", "content": [{"text": "Can you help me with a payment as my user is 2025 and I have to pay an amount of 520dt and I am using PayPal?"}]}
    ]
    
    # Run conversations
    azure_response = azure_agent.run_conversation(azure_messages)
    aws_response = aws_agent.run_conversation(aws_messages)
    
    print("Azure Response:", azure_response)
    print("AWS Response:", aws_response)

if __name__ == "__main__":
    main()