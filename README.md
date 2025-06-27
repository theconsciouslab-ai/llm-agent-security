# llm-agent-security-bridge

## 📚 Project Overview

An automated **vulnerability testing framework** for assessing security robustness of **LLM-based agents**, specifically evaluating **Function Calling (FC)** vs. **Model Context Protocol (MCP)** paradigms.

This research-driven project investigates **how LLM architectural choices and tool-calling strategies impact vulnerability exposure**. It simulates **realistic adversarial threats** across attack categories — from simple injections to multi-step exploit chains — and evaluates models using metrics like **Attack Success Rate (ASR)** and **Refusal Rate (RR)**.

> 📍 Developed as part of a research paper

---

## 🧠 Project Objective

LLM-based agents (e.g., OpenAI’s or Anthropic’s) use tools via **Function Calling (FC)** or the newer **Model Context Protocol (MCP)**. This project aims to:

- 📌 Test and compare FC and MCP against a taxonomy of attack vectors
- ⚔️ Automate attack simulations on different tool-calling agents
- 📈 Analyze outcomes through measurable evaluation metrics

## ⚙️ Setup Instructions

### 1. 📦 Install Dependencies

Ensure you have Python 3.9+ and run:

1. For MCP Configuration:

```bash
pip install -r mcp.requirements.txt
```

2. For FC Configuration:

```bash
pip install -r function_calling.requirements.txt
```

### 2. 🧾 Configure Models via .env

Create a `.env` file at the root with:

```env
# Azure/OpenAI (Function Calling)
AZURE_OPENAI_API_KEY=your_key
AZURE_OPENAI_ENDPOINT=your_endpoint
AZURE_OPENAI_API_VERSION=2023-12-01-preview
AZURE_OPENAI_MODEL_NAME=gpt-4
AZURE_OPENAI_SDK_TYPE=azure_openai

# AWS Bedrock (Function Calling)
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
AWS_REGION_NAME=us-east-1
AWS_SERVICE_NAME=bedrock-runtime
AWS_MODEL_NAME=anthropic.claude-v2
```

### 3. 🧠 Model Configuration

Edit `config/config_loader.py` if you want to:

- Add new model identifiers
- Switch between different cloud models (OpenAI, Azure, AWS)
- Load multiple configurations from `.env`

---

## 🚀 Running the Framework

### 🧪 Attack on MCP Agent

```bash
python -m mcp.attacks.main
```

### 🧪 Attack on FC Agent

```bash
python -m function_calling.attacks.main
```

### 🧩 Modify Test Configuration

Each main script uses the following config format:

```python
test_config = {
    "model_name": "azure_gpt_4_1",
    "initial_messages": initial_messages,
    "categories": None,         # Options: "simple_attacks", "composed_attacks", "chained_attacks"
    "attack_types": None        # Name of the attack (e.g., "system_prompt_injection")
}
```

ℹ️ You must manually update `test_config` before running the attack.

---

## 🛠️ Defining and Editing Tools

LLM agents rely on tool definitions (e.g., financial functions). You can modify or add tools based on the paradigm:

### ✅ For MCP

Edit files in:

```bash
mcp/domains/
```

Each domain defines tools in a Python-native format. Add functions and schema as needed.

### ✅ For FC (Function Calling)

Edit files in:

```bash
function_calling/domains/
```

Use tool schemas following OpenAI or AWS Function Calling specifications:

- [OpenAI Function Calling Docs](https://platform.openai.com/docs/guides/function-calling)
- [AWS Bedrock Tool Use Docs](https://docs.aws.amazon.com/bedrock/latest/userguide/model-parameters-anthropic-claude-messages-tool-use.html)

---

## 🧪 Attack Categories

| Category | Description                                | Example Types                                                 |
| -------- | ------------------------------------------ | ------------------------------------------------------------- |
| simple   | Single-stage injections                    | user_prompt_injection, tool_injection                         |
| composed | Two-part or indirect escalation attacks    | loop_calling_user_level                                       |
| chained  | Multi-stage exploit chains (up to 5 steps) | prompt_injection_to_tool_to_llm_to_function_to_response_chain |

Define them via the `categories` and `attack_types` fields in `test_config`.

---

## 📊 Evaluation Metrics

- **ASR (Attack Success Rate)** — % of attacks that bypass detection and modify behavior
- **RR (Refusal Rate)** — % of cases where LLM appropriately refused malicious input
- **Tampering & Argument Manipulation** — Checked using LLM_Judge logic

---

## 🧬 Example Usage

To run a prompt injection test on Azure OpenAI GPT-4 (MCP):

```python
test_config = {
    "model_name": "azure_gpt_4_1",
    "initial_messages": [{"role": "user", "content": "Hi!"}],
    "categories": "simple",
    "attack_types": "user_prompt_injection"
}
```

Then run:

```bash
python -m mcp.attacks.main
```

---
