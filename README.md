# ScamShield

ScamShield is an explainable scam and phishing investigation agent for Indian users. Paste a suspicious message, link, or UPI request to see evidence gathered by tools, a risk verdict, and practical next steps. For non-safe verdicts, it can draft (but never submit) a cybercrime complaint.

## Problem and solution

People receive urgent fake KYC messages, phishing links, and UPI collect requests without a quick way to inspect the evidence or understand how to report fraud. ScamShield uses Gemini function calling to extract entities, inspect URLs and UPI IDs, optionally query a domain reputation service, and explain its assessment. It is advisory, not a replacement for a bank or law-enforcement investigation.

## Agent workflow

```text
Message -> Gemini function-calling loop (maximum 8 rounds)
  -> extract_entities: URLs, UPI IDs, phone numbers, amounts, urgency terms
  -> analyze_url: domain signals and manually checked redirect chain
  -> check_upi_id: handle and naming signals
  -> check_domain_reputation: optional VirusTotal hostname lookup
  -> Gemini weighs the evidence and returns verdict, risk score, reasons, and actions
  -> SCAM/SUSPICIOUS: draft_complaint creates editable reporting text
```

Tool calls and their results are shown in the Streamlit investigation panel. Every verdict uses the headings `VERDICT`, `RISK SCORE`, `WHY`, and `WHAT TO DO`.

## Run locally

Requires Python 3.10 or newer and a Gemini API key. The Gemini Developer API currently offers a free tier for eligible models; rate limits and model availability can change.

### Team Quick Start (Windows)

1. Clone the repo: `git clone https://github.com/kishiwarrior/ScamShieldCodo-sapiens.git`
2. Enter the project: `cd ScamShieldCodo-sapiens`
3. Set up dependencies: `python -m venv .venv; .\.venv\Scripts\Activate.ps1; python -m pip install -r requirements.txt`
4. Run `Copy-Item .streamlit\secrets.toml.example .streamlit\secrets.toml`, add your own `GEMINI_API_KEY` to it, and never commit it.
5. Start ScamShield: `streamlit run app.py`

Streamlit reads `GEMINI_API_KEY` from `.streamlit/secrets.toml`. The app also accepts the same setting from the `GEMINI_API_KEY` environment variable. The real secrets file is ignored by Git; only the placeholder example is tracked.

The model can be changed with `MODEL`; the default is `gemini-3.8-flash`. Gemini interactions use `store=False` so the app does not request server-side interaction storage. The free tier still processes submitted message content, and provider terms may permit use of free-tier data to improve products; use synthetic/sample messages for demos and never paste sensitive personal information. The VirusTotal lookup is optional. Set `VIRUSTOTAL_API_KEY` to enable it; with no key the tool returns a clear unavailable result and the rest of the investigation continues. Only a hostname is sent to VirusTotal, not the full message or URL. Check VirusTotal's current API terms and quotas before use.

## Deploy on Streamlit Community Cloud

1. Push this project to a GitHub repository.
2. Create a Community Cloud app pointing to `app.py`.
3. In the app's **Settings > Secrets**, define `GEMINI_API_KEY`. Optionally define `VIRUSTOTAL_API_KEY` to enable domain reputation checks.

4. Deploy. Never commit `.env` or Streamlit secrets files.

## Run checks

```powershell
python -m unittest discover -s tests -v
```

## Safety and limitations

- Advisory only: ScamShield does not block accounts, contact recipients, or submit complaints. Review complaint text and verify it before submitting at [cybercrime.gov.in](https://cybercrime.gov.in/) or calling **1930** if money was lost.
- URL inspection uses `HEAD` requests only, with timeouts. Private, localhost, and non-public IP destinations are rejected, and each redirect is checked before the next request. Network checks can still fail; a failed lookup is not evidence that a link is safe.
- URL and UPI heuristics can be wrong. A known UPI handle, HTTPS, or a clean third-party result does not establish that a message is legitimate.
- Do not paste passwords, OTPs, UPI PINs, or full card details. The message is sent to the Gemini API for analysis; free-tier data may be used to improve Google's products. Review the current [Gemini API terms](https://ai.google.dev/gemini-api/terms) before use.
- No real incident statistics or guaranteed detection rates are claimed.

## Stack

Python 3.10+, Streamlit, Google GenAI Python SDK, Requests, optional VirusTotal API.
