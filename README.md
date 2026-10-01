# ScamShield

ScamShield is an explainable scam and phishing investigation agent for Indian users. Analyze suspicious messages, links, or UPI collect requests to see evidence gathered by security tools, a risk verdict, and practical next steps. For non-safe verdicts, it drafts an editable cybercrime complaint ready for filing.

## Problem and Solution

People receive urgent fake KYC messages, phishing links, and UPI collect requests without a quick way to inspect the evidence or understand how to report fraud. ScamShield uses Gemini function calling combined with a deterministic Heuristic Fallback Threat Engine to extract entities, inspect URLs and UPI IDs, optionally query a domain reputation service, and explain its assessment. It is advisory, not a replacement for a bank or law-enforcement investigation.

## Agent Workflow & Fallback Resilience

```text
Input Message
  │
  ├──► [Primary] Gemini Agent Tool-Calling Loop (up to 8 rounds)
  │      ├─► extract_entities: URLs, UPI IDs, phone numbers, amounts, urgency terms
  │      ├─► analyze_url: domain spoofing, suspicious TLDs, APK links, SSRF/redirect checks
  │      ├─► check_upi_id: handle whitelist and fraudulent naming keywords
  │      └─► check_domain_reputation: optional VirusTotal hostname lookup
  │
  └──► [Fallback Resilience Engine]
         └─► Activated automatically if Gemini API key is missing, network fails, or quota limit (429) is reached.
             Applies rule-based scoring and formats evidence; URL checks may still depend on network availability.
```

---

## REST API (Hackathon Evaluation Endpoint)

For evaluators and judges running automated evaluation or integration tests, ScamShield provides a production-grade FastAPI service.

### 1. Start the API Server
```powershell
# Using uvicorn
uvicorn api:app --host 0.0.0.0 --port 8000

# Or run directly
python api.py
```

- **Interactive Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc Documentation**: [http://localhost:8000/redoc](http://localhost:8000/redoc)
- **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

### 2. Endpoints

#### `POST /api/v1/investigate` (or alias `POST /investigate`)
Accepts either `{"text": "..."}` or `{"message": "..."}`.

**Sample Request:**
```json
{
  "text": "Dear customer, your SBI account will be blocked today. Update KYC immediately: http://sbi-kyc-update.xyz/login"
}
```

**Sample Response:**
```json
{
  "status": "success",
  "verdict": "SCAM",
  "risk_score": 90,
  "why": [
    "Deceptive domain 'sbi-kyc-update.xyz': mentions brand/term 'sbi' but is not the official domain",
    "Domain uses high-risk TLD: suspicious top-level domain",
    "Coercive/threat keywords detected: blocked",
    "Urgency indicators found: immediately, kyc"
  ],
  "actions": [
    "1. DO NOT click any links, download files, or approve UPI payment requests.",
    "2. Never enter your UPI PIN to receive money; entering a PIN always debits your account.",
    "3. Block the sender number immediately.",
    "4. If financial loss occurred, call national cybercrime helpline 1930 immediately within the golden hour.",
    "5. Register an official cyber incident at cybercrime.gov.in."
  ],
  "entities": {
    "urls": ["http://sbi-kyc-update.xyz/login"],
    "upi_ids": [],
    "phone_numbers": [],
    "amounts": [],
    "urgency_words": ["blocked", "immediately", "kyc"]
  },
  "complaint": "To: National Cyber Crime Reporting Portal (cybercrime.gov.in) / Helpline 1930\nCategory: Online Financial Fraud / Phishing...",
  "engine": "gemini_agent",
  "fallback_reason": null
}
```

#### `GET /api/v1/samples`
Returns preloaded test cases for quick evaluator verification.

---

## Run Locally (Streamlit UI)

Requires Python 3.10 or newer.

```powershell
# 1. Setup virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

# 2. Configure secrets (optional if testing with fallback heuristics)
Copy-Item .streamlit\secrets.toml.example .streamlit\secrets.toml
# Add your GEMINI_API_KEY inside .streamlit\secrets.toml

# 3. Launch Streamlit UI
streamlit run app.py
```

---

## Run Test Suite

Run all 19 automated unit tests across the security tools, fallback engine, and FastAPI endpoints:

```powershell
python -m unittest discover -s tests -v
```

---

## Safety and Limitations

- **Advisory Only**: ScamShield does not block accounts or submit complaints automatically. Review complaint text before submitting at [cybercrime.gov.in](https://cybercrime.gov.in/) or calling **1930**.
- **SSRF Protection**: URL inspection uses `HEAD` requests only with strict timeouts. Private, localhost, and non-public IP destinations are blocked.
- **Privacy**: Gemini calls use `store=False` to opt out of server-side interaction storage. This is not a zero-retention guarantee; Google's data handling terms still apply. Do not submit sensitive personal information.
- **Fallback Design**: If Gemini is unavailable or rate limited, the heuristic engine can still provide an assessment. Network-based URL checks may be unavailable, and fallback does not guarantee uninterrupted service.

## Stack

Python 3.10+, FastAPI, Streamlit, Google GenAI SDK, Requests, Uvicorn, Pydantic.
