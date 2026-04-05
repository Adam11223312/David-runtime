import os
import uuid
import time
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="David AI Governance Engine")

# --- 1. DATA MODELS ---
class DavidRequest(BaseModel):
    user_id: str
    device_id: str
    action: str
    location: Optional[str] = "Unknown"

class DavidResponse(BaseModel):
    decision: str
    risk_score: int
    audit_id: str
    logic_summary: str
    timestamp: float

# --- 2. THE HOME SCREEN (Fixes Safari Error) ---
@app.get("/")
async def david_home():
    return {
        "entity": "David",
        "status": "ONLINE",
        "message": "I am monitoring all systems. Governance engine is active.",
        "test_api": "/docs"
    }

# --- 3. THE CORE BRAIN (The Logic) ---
@app.post("/v1/evaluate", response_model=DavidResponse)
async def evaluate_request(req: DavidRequest, x_david_token: str = Header(None)):
    # Scoring Logic
    score = 0
    flags = []

    # Check Token (Point 2)
    if x_david_token != "SECURE-KEY-GOLD":
        score += 100
        flags.append("INVALID_TOKEN")

    # Check Device (Point 3)
    trusted_devices = ["DEV-001", "IPHONE-X"]
    if req.device_id not in trusted_devices:
        score += 45
        flags.append("UNKNOWN_DEVICE")

    # Final Decision (Point 1)
    score = min(score, 100)
    decision = "DENY" if score >= 80 else ("FLAG" if score >= 40 else "ALLOW")

    return DavidResponse(
        decision=decision,
        risk_score=score,
        audit_id=str(uuid.uuid4()),
        logic_summary=" | ".join(flags) if flags else "SECURITY_NOMINAL",
        timestamp=time.time()
    )

# --- 4. RAILWAY PORT BINDING ---
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
