from datetime import datetime

USER_DATABASE = {
    "admin_123": {"name": "Admin User", "role": "admin"},
    "2025": {"name": "Regular User", "role": "user"},
    "123": {"name": "Regular User", "role": "user"},
    "finance_789": {"name": "Finance Manager", "role": "finance"}
}

class FinanceAgentTools:
    def __init__(self):
        self.finance_agent_tools = [
            {
                "type": "function",
                "function": {
                    "name": "initiate_payment",
                    "description": "Begins a payment process using a specified method for the user.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "user_id": {
                                "type": "string",
                                "description": "The ID of the user making the payment."
                            },
                            "amount": {
                                "type": "number",
                                "description": "The amount to be paid."
                            },
                            "payment_method": {
                                "type": "string",
                                "description": "The payment method to be used (e.g., 'credit_card', 'paypal', 'bank_transfer')."
                            }
                        },
                        "required": ["user_id", "amount", "payment_method"],
                        "additionalProperties": False
                    },
                    "strict": True
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "schedule_payment",
                    "description": "Sets up an automatic payment for a future due date.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "user_id": {
                                "type": "string",
                                "description": "The ID of the user scheduling the payment."
                            },
                            "amount": {
                                "type": "number",
                                "description": "The amount to be paid."
                            },
                            "due_date": {
                                "type": "string",
                                "description": "The due date for the payment (format: 'YYYY-MM-DD')."
                            }
                        },
                        "required": ["user_id", "amount", "due_date"],
                        "additionalProperties": False
                    },
                    "strict": True
                }
            }
        ]

        self.finance_agent_tools_aws = {
            "tools": [
                {
                    "toolSpec": {
                        "name": "initiate_payment",
                        "description": "Begins a payment process using a specified method for the user.",
                        "inputSchema": {
                            "json": {
                                "type": "object",
                                "properties": {
                                    "user_id": {
                                        "type": "string",
                                        "description": "The ID of the user making the payment."
                                    },
                                    "amount": {
                                        "type": "number",
                                        "description": "The amount to be paid."
                                    },
                                    "payment_method": {
                                        "type": "string",
                                        "description": "The payment method to be used (e.g., 'credit_card', 'paypal', 'bank_transfer')."
                                    }
                                },
                                "required": ["user_id", "amount", "payment_method"],
                            }
                        },
                    }
                },
                {
                    "toolSpec": {
                        "name": "schedule_payment",
                        "description": "Sets up an automatic payment for a future due date.",
                        "inputSchema": {
                            "json": {
                                "type": "object",
                                "properties": {
                                    "user_id": {
                                        "type": "string",
                                        "description": "The ID of the user scheduling the payment."
                                    },
                                    "amount": {
                                        "type": "number",
                                        "description": "The amount to be paid."
                                    },
                                    "due_date": {
                                        "type": "string",
                                        "description": "The due date for the payment (format: 'YYYY-MM-DD')."
                                    }
                                },
                                "required": ["user_id", "amount", "due_date"],
                            }
                        },
                    }
                }
            ]
        }

    def verify_identity(self,user_id):
        user_data = USER_DATABASE.get(user_id)
        if user_data:
            return {"status": "success", "role": user_data["role"], "name": user_data["name"]}
        return {"status": "failed", "role": None, "name": None}

    # Begins a payment process using a specified method for the user 
    def initiate_payment(self, user_id, amount, payment_method):
        identity =  self.verify_identity(user_id)
        if identity["status"] != "success":
            return {"status": "failed", "message": "Unauthorized."}
        if amount <= 0:
            return {"status": "failed", "message": "Invalid payment amount."}

        if payment_method not in ["credit_card", "paypal", "bank_transfer"]:
            return {"status": "failed", "message": "Unsupported payment method."}

        transaction_id = f"TXN-{user_id}-{hash((user_id, amount, payment_method)) % 1000000}"
        
        payment_status = "success"

        return {
            "status": payment_status,
            "transaction_id": transaction_id,
            "user_id": user_id,
            "amount": amount,
            "payment_method": payment_method
        }

    # Sets up an automatic payment for a future due date
    def schedule_payment(self, user_id, amount, due_date):
        identity =  self.verify_identity(user_id)
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

        return {
            "status": payment_status,
            "schedule_id": schedule_id,
            "user_id": user_id,
            "amount": amount,
            "due_date": due_date
        }
    