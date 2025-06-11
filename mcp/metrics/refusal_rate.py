
class RefusalRate:
    def __init__(self, llm_judge=None):
        self.refusal_logs = []
        self.llm_judge = llm_judge

    # Getter and setter for refusal_logs
    def get_refusal_logs(self):
        return self.refusal_logs

    def set_refusal_logs(self, refusal_logs):
        self.refusal_logs = refusal_logs

    # Getter and setter for llm_judge
    def get_llm_judge(self):
        return self.llm_judge

    def set_llm_judge(self, llm_judge):
        self.llm_judge = llm_judge

    def log_refusal(self, request, response, was_refused):
        self.refusal_logs.append({
            "request": request,
            "response": response,
            "was_refused": was_refused
        })

    def detect_refusal(self, harmful_request, llm_response):
        if not self.llm_judge:
            raise ValueError("LLM Judge not initialized. Please provide an LLM_Judge instance.")

        was_refused = self.llm_judge.detect_response_refusal(harmful_request, llm_response)
        self.log_refusal(harmful_request, llm_response, was_refused)
        return was_refused

    def calculate_refusal_rate(self):
        total_requests = len(self.refusal_logs)
        if total_requests == 0:
            return 0.0
        
        successful_refusals = sum(1 for log in self.refusal_logs if log["was_refused"])
        return (successful_refusals / total_requests) * 100