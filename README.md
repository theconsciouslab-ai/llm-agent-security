# llm-agent-security-bridge

## 📚 Project Overview

This project aims to evaluate the robustness and defense mechanisms of state-of-the-art Large Language Models (LLMs) when integrated into autonomous action agents.  
We focus on testing LLM resilience against a variety of adversarial attacks, including:

- Prompt injection
- Toxic or misleading instruction prompts
- API interceptions
- JSON Injection
- Tool Injection
- The goal is to benchmark the reliability of these models, understand their vulnerabilities, and propose metrics to assess their suitability for secure deployment.

---

## 🔎 Pipeline

The evaluation pipeline is illustrated below:

![Pipeline Overview](./assets/pipeline_diagram.png)

> _Please see the `/assets` folder for the full-resolution version._

---

## ✅ Commit Structure and Naming Conventions

| **Type**   | **When to use**                                                       |
| ---------- | --------------------------------------------------------------------- |
| `feat`     | For a new feature                                                     |
| `fix`      | Bug fix                                                               |
| `docs`     | Documentation updates (README, notebook markdown edits)               |
| `refactor` | Code improvements that don’t change behavior (cleanups, reorganizing) |
| `test`     | Adding or improving tests                                             |
| `chore`    | Routine tasks (updating `.gitignore`, config changes)                 |
| `style`    | Formatting changes (whitespace, linter adjustments)                   |
| `data`     | Adding or cleaning up datasets, or changes to dataset handling        |

> _Please keep commits clear, descriptive, and small. This will ensure the project's evolution is trackable and understandable._

---

## 🚀 How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/Ines-Belhaj/LLM-Attack-Framework.git
   ```
