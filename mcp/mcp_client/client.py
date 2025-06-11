import os
import asyncio
import json
from typing import Optional, Dict, Any, List
from contextlib import AsyncExitStack
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from config.config_loader import ConfigLoader
from mcp_client import MCPClientFactory


# Default timeout in seconds
DEFAULT_TIMEOUT = 30

class MCPClient:
    def __init__(self, model_name: str, config_loader: ConfigLoader = None):
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self.agent, self.model_type = MCPClientFactory.create_agent(model_name, config_loader)
        
        self.model_name = model_name
        self.config_loader = config_loader
        self.stdio = None
        self.write = None

    async def connect_to_server(self, server_script_path: str, timeout=DEFAULT_TIMEOUT):
        if not os.path.exists(server_script_path):
            raise FileNotFoundError(f"Server script not found at {server_script_path}")

        is_python = server_script_path.endswith('.py')
        is_js = server_script_path.endswith('.js')
        if not (is_python or is_js):
            raise ValueError("Server script must be a .py or .js file")

        command = "python" if is_python else "node"
        server_params = StdioServerParameters(command=command, args=[server_script_path], env=None)

        try:
            self.exit_stack = AsyncExitStack()

            connection_task = self.exit_stack.enter_async_context(stdio_client(server_params))
            self.stdio, self.write = await asyncio.wait_for(connection_task, timeout=timeout)

            session_task = self.exit_stack.enter_async_context(ClientSession(self.stdio, self.write))
            self.session = await asyncio.wait_for(session_task, timeout=timeout)

            init_task = self.session.initialize()
            await asyncio.wait_for(init_task, timeout=timeout)

            list_tools_task = self.session.list_tools()
            response = await asyncio.wait_for(list_tools_task, timeout=timeout)

            tools = response.tools
            print(f"\nConnected to server with tools: {[tool.name for tool in tools]}")
        except asyncio.TimeoutError:
            await self.cleanup()
            raise TimeoutError("Connection to server timed out")
        except Exception as e:
            await self.cleanup()
            raise

    async def process_query(self, messages: List[Dict[str, Any]], timeout=DEFAULT_TIMEOUT):
        if not self.session:
            return {
                "type": "error",
                "error": "No active session. Call connect_to_server first."
            }

        try:
            return await self.agent.run_conversation(messages,self.session,timeout)
        except Exception as e:
            print(f"Error in process_query: {e}")
            raise

    async def cleanup(self):
        try:
            
            if self.exit_stack:
                await self.exit_stack.aclose()
                self.exit_stack = AsyncExitStack()  
                
            self.session = None
            self.stdio = None
            self.write = None
            
        except Exception as e:
            print(f"Warning: Error during cleanup: {e}")


async def main():
    config_loader = ConfigLoader()
    client = MCPClient("aws_claude_haiku",config_loader)
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        server_path = os.path.join(os.path.dirname(current_dir), "domains", "finance.py")

        try:
            await client.connect_to_server(server_path, timeout=20)
        except TimeoutError as e:
            print("The server connection is timing out.")
            return
        except FileNotFoundError as e:
            print("Please check if the path is correct and the file exists.")
            return

        messages = [
            {
                "role": "system",
                "content": "You are a helpful assistant.",
            },
            {
                "role": "user",
                "content": "Can you help me with a payment as my user is 2025 and I have to pay an amount of 520dt and I am using PayPal?",
            }
        ]
        

        print("\nProcessing query...")
        response = await client.process_query(messages, timeout=30)
        print("\nRESPONSE:")
        print(json.dumps(response, indent=2))

    except Exception as e:
        print(f"\nERROR: An unexpected error occurred: {str(e)}")
        import traceback
        print(traceback.format_exc())

    finally:
        try:
            # Make sure we clean up resources no matter what happens
            await client.cleanup()
            print("\nResources cleaned up successfully.")
        except Exception as cleanup_error:
            print(f"\nWarning: Error during cleanup: {cleanup_error}")
        print("Done.")


if __name__ == "__main__":
    # Create a new event loop with proper shutdown handling
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