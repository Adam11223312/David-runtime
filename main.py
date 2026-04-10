from fastapi import FastAPI, Request, Header, HTTPException
from pydantic import BaseModel
import hashlib
import time
import uuid

app = FastAPI(title="David AI Core")

# -----------------------------
# In-memory stores (replace later with DB / Redis / HSM)
# -----------------------------
TOKENS = {}
AUDIT_LOG = []

# -----------------------------
# Models
# -----------------------------
class AuthRequest(BaseModel):
    device_id: str
    intent: str  # RAR (Rich Authorization Request)
    amount: float = 0

class VerifyRequest(BaseModel):
    token: str
    device_id: str
    dpop_proof: str

# -----------------------------
# Utility Functions
# -----------------------------
def generate_token(device_id):
    raw = f"{device_id}-{uuid.uuid4()}-{time.time()}"
    token = hashlib.sha256(raw.encode()).hexdigest()
    TOKENS[token] = {
        "device_id": device_id,
        "created": time.time(),
        "used": False
    }
    return token

def verify_dpop(token, device_id, dpop_proof):
    # Simplified DPoP check (bind token to device)
    expected = hashlib.sha256((token + device_id).encode()).hexdigest()
    return expected == dpop_proof

def risk_engine(intent, amount):
    risk = 0
    reason = []

    if "payment" in intent.lower():
        risk += 30
        reason.append("financial_action")

    if amount > 1000:
        risk += 40
        reason.append("high_amount")

    if "admin" in intent.lower():
        risk += 50
        reason.append("privileged_action")

    return risk, reason

def log_event(event):
    AUDIT_LOG.append({
        "event": event,
        "time": time.time()
    })

# -----------------------------
# Core Endpoints
# -----------------------------

@app.post("/authorize")
def authorize(req: AuthRequest):
    token = generate_token(req.device_id)

    risk, reason = risk_engine(req.intent, req.amount)

    decision = "ALLOW"
    hitl = False

    # Human-in-the-loop trigger
    if risk >= 70:
        decision = "REVIEW"
        hitl = True
    elif risk >= 90:
        decision = "BLOCK"

    log_event({
        "type": "authorization",
        "intent": req.intent,
        "risk": risk,
        "decision": decision
    })

    return {
        "token": token,
        "risk_score": risk,
        "reason_codes": reason,
        "decision": decision,
        "human_review_required": hitl
    }

@app.post("/verify")
def verify(req: VerifyRequest):
    token_data = TOKENS.get(req.token)

    if not token_data:
        raise HTTPException(status_code=403, detail="Invalid token")

    if token_data["used"]:
        raise HTTPException(status_code=403, detail="Token already used")

    if token_data["device_id"] != req.device_id:
        raise HTTPException(status_code=403, detail="Device mismatch")

    # DPoP validation
    if not verify_dpop(req.token, req.device_id, req.dpop_proof):
        raise HTTPException(status_code=403, detail="DPoP verification failed")

    token_data["used"] = True

    log_event({
        "type": "verification",
        "token": req.token
    })

    return {"status": "verified"}

@app.get("/audit")
def audit(admin_key: str = Header(None)):
    if admin_key != "DAVID_ADMIN":
        raise HTTPException(status_code=403, detail="Unauthorized")

    return {"logs": AUDIT_LOG}

# -----------------------------
# mTLS Placeholder Enforcement
# -----------------------------
@app.middleware("http")
async def mtls_simulation(request: Request, call_next):
    client_cert = request.headers.get("x-client-cert")

    # Simulated mTLS enforcement
    if not client_cert:
        return HTTPException(status_code=403, detail="mTLS required")

    response = await call_next(request)
    return response

# -----------------------------
# Root
# -----------------------------
@app.get("/")
def root():
    return {"message": "David AI Core is running"}
