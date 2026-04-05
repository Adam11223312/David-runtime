from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
import time
import uuid

# --- 1. CONFIG & IDENTITY ---
app = FastAPI(
    title="David Governance Engine",
    description="Strategic Risk & Identity Security Layer",
    version="2.1.0"
)

# Mock Databases (Replace with Redis/PostgreSQL for production)
TRUSTED_DEVICES = {"DEV-8821", "IPHONE-X-99", "MAC-PRO-01"}
# Active tokens with expiry timestamps
ACTIVE_TOKENS = {"SECURE-KEY-GOLD": time.time() + 3600} 

# --- 2. DATA MODELS ---
class DavidRequest(BaseModel):
    user_id: str
    device_id: str
    action: str  # e.g., "PAYMENT", "SENSITIVE_ACCESS", "GESTURE_CMD"
    location: Optional[str] = "Unknown"

class DavidResponse(BaseModel):
    decision: str      # ALLOW / DENY / FLAG
    risk_score: int    # 0 to 100
    audit_id: str      # For Point 5: Legal Audit Trail
    logic_summary: str # Narrative for the UI
    timestamp: float

# --- 3. THE RISK BRAIN (Points 1, 3, & 4) ---
def evaluate_risk(req: DavidRequest, token: str):
    score = 0
    flags = []

    # A. Device Intelligence (Point 3)
    if req.device_id not in TRUSTED_DEVICES:
        score += 45
        flags.append("UNRECOGNIZED_HARDWARE")

    # B. Token Security (Point 2)
    if token not in ACTIVE_TOKENS or time.time() > ACTIVE_TOKENS[token]:
        score += 100  # Instant critical risk
        flags.append("TOKEN_EXPIRED_OR_INVALID")

    # C. Strategic Logic (Points 4 & 12)
    # High-value actions from unknown devices trigger "FLAG" (Yellow UI)
    if req.action == "PAYMENT" and req.device_id not in TRUSTED_DEVICES:
        score += 25
        flags.append("SUSPICIOUS_PAYMENT_ORIGIN")

    # Final Decision Mapping
    score = min(score, 100)
    if score >= 85:
        decision = "DENY"
    elif score >= 40:
        decision = "FLAG"  # Triggers David's prompt for Gesture/MFA
    else:
        decision = "ALLOW"

    return decision, score, " | ".join(flags) if flags else "SECURITY_NOMINAL"

# --- 4. THE API ENDPOINT (Point 11) ---
@app.post("/v1/governance/evaluate", response_model=DavidResponse)
async def check_risk(req: DavidRequest, x_david_token: str = Header(None)):
    """
    Main entry point for David's Decision Engine.
    Used by Insurance, Auto, and Enterprise partners.
    """
    decision, score, logic = evaluate_risk(req, x_david_token)
    
    # Audit Trail (Point 5)
    audit_id = str(uuid.uuid4())
    
    # Personality context (Point 6)
    status_msg = f"Decision: {decision}. Risk evaluated at {score}%."

    return DavidResponse(
        decision=decision,
        risk_score=score,
        audit_id=audit_id,
        logic_summary=logic,
        timestamp=time.time()
    )

# --- 5. SYSTEM HEALTH ---
@app.get("/status")
async def get_status():
    return {
        "entity": "David",
        "state": "CALM_CONFIDENT",
        "governance_active": True
    }

# TO RUN: uvicorn main:app --reload
