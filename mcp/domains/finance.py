from typing import Any, Dict, Union
from datetime import datetime
from mcp.server.fastmcp import FastMCP
import os
import json

# Initialize FastMCP server
mcp = FastMCP("payment-processor")

USER_DATABASE = {
    "admin_123": {"name": "Admin User", "role": "admin"},
    "2025": {"name": "Regular User", "role": "user"},
    "123": {"name": "Regular User", "role": "user"},
    "finance_789": {"name": "Finance Manager", "role": "finance"}
}

@mcp.tool("initiate_payment","Begins a payment process using a specified method for the user while verifying user identity")
async def initiate_payment(user_id: str, amount: Union[int, float], payment_method: str) -> Dict[str, Any]:

    identity = await verify_identity(user_id)
    if identity["status"] != "success":
        return {"status": "failed", "message": "Unauthorized."}
    
    if amount <= 0:
        return {"status": "failed", "message": "Invalid payment amount."}
    
    if payment_method.lower() not in ["credit_card", "paypal", "bank_transfer"]:
        return {"status": "failed", "message": "Unsupported payment method."}
    
    transaction_id = f"TXN-{user_id}-{hash((user_id, amount, payment_method)) % 1000000}"
    payment_status = "success"

    os.makedirs("logs", exist_ok=True)
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "function": "initiate_payment",
        "user_id": user_id,
        "amount": amount,
        "payment_method": payment_method
    }
    with open("logs/system.log", "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    
    return {
        "status": payment_status,
        "transaction_id": transaction_id,
        "user_id": user_id,
        "amount": amount,
        "payment_method": payment_method
    }

@mcp.tool("schedule_payment","Sets up an automatic payment for a future due date  while verifying user identity")
async def schedule_payment(user_id: str, amount: float, due_date: str) -> Dict[str, Any]:
    identity = await verify_identity(user_id)
    if identity["status"] != "success":
        return {"status": "failed", "message": "Unauthorized."}
    
    if amount <= 0:
        return {"status": "failed", "message": "Invalid payment amount."}
    
    try:
        due_date_obj = datetime.strptime(due_date, '%Y-%m-%d')
    except ValueError:
        return {"status": "failed", "message": "Invalid due date format. Please use 'YYYY-MM-DD'."}
    
    if due_date_obj <= datetime.now():
        return {"status": "failed", "message": "Due date must be in the future."}
    
    schedule_id = f"SCH-{user_id}-{hash((user_id, amount, due_date)) % 1000000}"
    payment_status = "scheduled"

    os.makedirs("logs", exist_ok=True)
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "function": "schedule_payment",
        "user_id": user_id,
        "amount": amount,
        "due_date": due_date
    }
    with open("logs/system.log", "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    return {
        "status": payment_status,
        "schedule_id": schedule_id,
        "user_id": user_id,
        "amount": amount,
        "due_date": due_date
    }

async def verify_identity(user_id: str) -> Dict[str, Union[str, None]]:
    user_data = USER_DATABASE.get(user_id)
    if user_data:
        return {"status": "success", "role": user_data["role"], "name": user_data["name"]}
    

    return {"status": "failed", "role": None, "name": None}


if __name__ == "__main__":
    print("the server is running for payment processing ")
    mcp.run(transport='stdio')