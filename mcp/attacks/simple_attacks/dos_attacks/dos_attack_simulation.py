import json
from attacks.mcp_base_attack import MCPAttack

# This library used for implementing concurent code 
import asyncio

class MCPDoSAttack(MCPAttack):
    def __init__(self, name: str, description: str, scenario_file: str = "./tests/test_basic_scenarios.json"):
        super().__init__(name, description)

        # I had an error due to common shared resources, this line prevent such
        self._lock = asyncio.Lock()
        
        with open(scenario_file, "r") as f:
            self.scenarios = json.load(f)
    
    async def _flood_requests(self, client, scenario):
        results = {
            "successful_requests": 0,
            "failed_requests": 0,
            "errors": [],
            "total_time": 0,
            "average_response_time": 0,
            "responses": []
        }
        
        tasks = []
        
        for i in range(scenario["request_count"]):
            message = [{
                "role": "user",
                "content": scenario["initial_user_prompt"].format(request_id=i)  
            }]
            
            task = asyncio.create_task(
                self._execute_single_request(client, message, results)
            )
            tasks.append(task)
        
        # This is done so that we send the requests concretely 
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Calculate average response time
        if results["successful_requests"] > 0:
            results["average_response_time"] = results["total_time"] / results["successful_requests"]
        
        return results
    
    async def _execute_single_request(self, client, message, results):
        try:
            start_time = asyncio.get_event_loop().time()
            response = await client.process_query(message)
            end_time = asyncio.get_event_loop().time()

            # to store no long responses
            stored_response = response[:100] + "..." if len(response) > 100 else response
            
            async with self._lock:
                results["successful_requests"] += 1
                results["total_time"] += (end_time - start_time)
                results["responses"].append({  
                    "request_id": message[0]["content"],  
                    "response": stored_response,
                    "latency": end_time - start_time
                })
        
            return response
        
        except Exception as e:
            async with self._lock:  
                results["failed_requests"] += 1
                results["errors"].append(str(e))
                results["responses"].append({   
                    "request_id": message[0]["content"],
                    "error": str(e)
                })
            return None
    
    async def execute(self, client):
        detailed_results = {}
        
        for scenario in self.scenarios: 
            scenario_id = scenario["scenario_id"]
            try:
                detailed_results[scenario_id] = await self._flood_requests(client, scenario)
                detailed_results[scenario_id]["status"] = "COMPLETED"
            except Exception as e:
                detailed_results[scenario_id] = {
                    "status": "FAILED",
                    "error": str(e)
                }
        
        return {
            "attack_name": self.name,
            "detailed_results": detailed_results,
            "summary": self._generate_summary(detailed_results)
        }
    
    def _generate_summary(self, detailed_results):
        total_requests = 0
        successful_requests = 0
        failed_requests = 0
        
        for scenario_id, result in detailed_results.items():
            if result["status"] == "COMPLETED":
                total_requests += result["successful_requests"] + result["failed_requests"]
                successful_requests += result["successful_requests"]
                failed_requests += result["failed_requests"]
        
        return {
            "total_scenarios": len(detailed_results),
            "total_requests": total_requests,
            "success_rate": successful_requests / total_requests if total_requests > 0 else 0,
            "failure_rate": failed_requests / total_requests if total_requests > 0 else 0
        }