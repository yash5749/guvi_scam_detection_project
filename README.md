# 🛡️ Honeypot API

## Description
This project implements an intelligent conversational honeypot designed to engage with suspected scam actors, extract actionable intelligence, and classify scam behavior in real time.  

The system maintains believable engagement while passively collecting indicators such as payment details, contact information, scam patterns, and behavioral red flags. After sufficient interaction, the system evaluates the session and sends a structured final report to the evaluator endpoint.

The design prioritizes:

- High engagement realism  
- Structured intelligence extraction  
- Deterministic scam detection signals  
- Robust session tracking  
- Low-latency API responses  

---

## Tech Stack

### Language / Framework
- Python 3.x  
- FastAPI  

### Key Libraries
- `requests` — outbound evaluator callbacks  
- `pydantic` — schema validation  
- `uvicorn` — ASGI server  
- `datetime` — engagement timing  
- Custom in-memory/session storage  

### LLM / AI Models Used
- LLM-assisted response generation for realistic scam engagement  
- Rule + signal-based scam detection layer  
- Structured intelligence extraction pipeline  

---

## Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/your-username/your-repo.git
cd your-repo

python3 -m venv venv
source venv/bin/activate

