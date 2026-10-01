"""ScamShield REST API (FastAPI) for Hackathon Evaluation."""
import logging
from typing import List, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, model_validator

from engine import investigate, MODEL

logger = logging.getLogger(__name__)

app = FastAPI(
    title="ScamShield API",
    description="Explainable cyber threat & scam investigation API for Indian users (phishing, fake KYC, UPI fraud).",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for universal evaluation access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class InvestigationRequest(BaseModel):
    text: Optional[str] = Field(default=None, description="The suspicious message, SMS, URL, or UPI collect text.")
    message: Optional[str] = Field(default=None, description="Alternative field name for text.")
    force_heuristic: bool = Field(default=False, description="Bypass LLM and directly run the rule-based threat engine.")

    @model_validator(mode="after")
    def check_text_or_message(self):
        content = (self.text or "").strip() or (self.message or "").strip()
        if not content:
            raise ValueError("Either 'text' or 'message' field must be provided and non-empty.")
        self.text = content
        return self


class EntitiesModel(BaseModel):
    urls: List[str] = Field(default_factory=list)
    upi_ids: List[str] = Field(default_factory=list)
    phone_numbers: List[str] = Field(default_factory=list)
    amounts: List[str] = Field(default_factory=list)
    urgency_words: List[str] = Field(default_factory=list)


class InvestigationResponse(BaseModel):
    status: str = "success"
    verdict: str = Field(description="Threat classification: SCAM, SUSPICIOUS, or SAFE")
    risk_score: int = Field(ge=0, le=100, description="Risk confidence score from 0 to 100")
    why: List[str] = Field(description="Citations and evidence for the verdict")
    actions: List[str] = Field(description="Recommended steps for the user")
    entities: EntitiesModel
    complaint: Optional[str] = Field(default=None, description="Drafted cybercrime complaint for 1930 / cybercrime.gov.in")
    engine: str = Field(description="Analysis engine utilized: gemini_agent or heuristic_fallback")
    fallback_reason: Optional[str] = None
    raw_text: Optional[str] = None


@app.get("/", tags=["General"])
def root():
    return {
        "name": "ScamShield Threat Intelligence API",
        "version": "1.0.0",
        "documentation": "/docs",
        "health": "/health",
        "description": "Analyze suspicious SMS, phishing URLs, and UPI fraud patterns with explainable AI and resilient local heuristics."
    }


@app.get("/health", tags=["General"])
def health_check():
    return {
        "status": "healthy",
        "service": "ScamShield",
        "active_model": MODEL,
        "features": {
            "gemini_tool_calling": True,
            "heuristic_fallback": True,
            "ssrf_protection": True,
            "apk_detection": True,
            "upi_heuristic": True
        }
    }


@app.get("/api/v1/samples", tags=["Samples"])
def get_sample_scenarios():
    """Retrieve preloaded scam test cases for evaluators."""
    return {
        "samples": [
            {
                "name": "Fake SBI KYC Phishing",
                "text": "Dear customer, your SBI account will be blocked today. Update KYC immediately: http://sbi-kyc-update.xyz/login"
            },
            {
                "name": "UPI Collect Request Fraud",
                "text": "Hi, I am sending your refund of Rs. 4,999. Please approve the collect request from refund.support8834@okybl and enter your UPI PIN."
            },
            {
                "name": "Electricity Bill Threat",
                "text": "URGENT: Your electricity connection will be DISCONNECTED tonight at 9:30 PM due to unpaid bill of Rs. 1,450. Call executive at +919876543210 or pay at http://bijli-bill-update.xyz/pay"
            },
            {
                "name": "Legitimate Bank Alert",
                "text": "Dear SBI Customer, your A/C ending with 4821 has been debited by INR 350.00 on 01-Oct-26 via UPI. Ref No 427819382104. If not done by you, visit https://www.sbi.co.in or call 18001234. Never share your OTP, UPI PIN, or CVV."
            }
        ]
    }


@app.post(
    "/api/v1/investigate",
    response_model=InvestigationResponse,
    summary="Investigate Suspicious Message or URL",
    tags=["Investigation"]
)
def investigate_endpoint(req: InvestigationRequest):
    """
    Main Threat Investigation Endpoint:
    - Runs multi-turn tool calling with Gemini agent when available.
    - Seamlessly fails over to deterministic Heuristic Threat Engine if LLM/API quota is unavailable.
    """
    try:
        result = investigate(req.text, force_heuristic=req.force_heuristic)
        return {
            "status": "success",
            "verdict": result["verdict"],
            "risk_score": result["risk_score"],
            "why": result.get("why", []),
            "actions": result.get("actions", []),
            "entities": result.get("entities", {}),
            "complaint": result.get("complaint"),
            "engine": result.get("engine", "unknown"),
            "fallback_reason": result.get("fallback_reason"),
            "raw_text": result.get("raw_text")
        }
    except Exception as exc:
        logger.error("Investigation endpoint failed (%s)", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Investigation failed. Please retry."
        )


# Alias route for automated evaluators expecting /investigate
@app.post("/investigate", response_model=InvestigationResponse, include_in_schema=False)
def investigate_alias(req: InvestigationRequest):
    return investigate_endpoint(req)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
