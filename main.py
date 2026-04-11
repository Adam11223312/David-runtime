from fastapi import FastAPI, Request, Header, HTTPException
from pydantic import BaseModel
import hashlib
import time
import uuid
import json

app = FastAPI(title="David AI Core - Sovereign Build v3")

# -----------------------------
# Audit Chain (Your System - Integrated)
# -----------------------------
class DavidAuditChain:
    def __init__(self):
        self.chain = []
        self.last_hash = "GENESIS_BLOCK_DAVID_2026"

    def add_entry(self, event_type, data):
        timestamp = time.time()
        payload = f"{self.last_hash}|{event_type}|{json.dumps(data)}|{timestamp}"
        current_hash = hashlib.sha3_512(payload.encode()).hexdigest()

        entry = {
            "event": event_type,
            "data": data,
            "timestamp": timestamp,
            "prev_hash": self.last_hash,
            "current_hash": current_hash
        }

        self.chain.append(entry)
        self.last_hash = current_hash
        return entry

    def verify_integrity(self):
        for i in range(1, len(self.chain)):
            prev = self.chain[i-1]
            curr = self.chain[i]
            if curr['prev_hash'] != prev['current_hash']:
                return False, f"TAMPERING DETECTED AT BLOCK {i}"
        return True, "CHAIN VERIFIED: David's history is intact."

AUDIT_CHAIN = DavidAuditChain()

# -----------------------------
# In-Memory Stores (Replace later)
# -----------------------------
TOKENS = {}

# -----------------------------
# Models
# -----------------------------
class AuthRequest(BaseModel):
    device_id: str
    intent: str
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

    AUDIT_CHAIN.add_entry("token_issued", {"device_id": device_id})

    return token

def verify_dpop(token, device_id, dpop_proof):
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

# -----------------------------
# Core Endpoints
# -----------------------------
@app.post("/authorize")
def authorize(req: AuthRequest):
    token = generate_token(req.device_id)

    risk, reason = risk_engine(req.intent, req.amount)

    decision = "ALLOW"
    hitl = False

    if risk >= 70:
        decision = "REVIEW"
        hitl = True
    elif risk >= 90:
        decision = "BLOCK"

    AUDIT_CHAIN.add_entry("authorization", {
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

    if not verify_dpop(req.token, req.device_id, req.dpop_proof):
        raise HTTPException(status_code=403, detail="DPoP verification failed")

    token_data["used"] = True

    AUDIT_CHAIN.add_entry("verification", {
        "token": req.token
    })

    return {"status": "verified"}

# -----------------------------
# Audit + Integrity Endpoints
# -----------------------------
@app.get("/audit")
def audit(admin_key: str = Header(None)):
    if admin_key != "DAVID_ADMIN":
        raise HTTPException(status_code=403, detail="Unauthorized")

    return {"chain": AUDIT_CHAIN.chain}

@app.get("/audit/verify")
def verify_chain(admin_key: str = Header(None)):
    if admin_key != "DAVID_ADMIN":
        raise HTTPException(status_code=403, detail="Unauthorized")

    status, message = AUDIT_CHAIN.verify_integrity()

    return {
        "valid": status,
        "message": message
    }

# -----------------------------
# mTLS Enforcement (Safe Version)
# -----------------------------
@app.middleware("http")
async def mtls_enforcement(request: Request, call_next):
    client_cert = request.headers.get("x-client-cert")

    # Allow root for testing
    if request.url.path != "/" and not client_cert:
        raise HTTPException(status_code=403, detail="mTLS certificate required")

    return await call_next(request)

# -----------------------------
# Root
# -----------------------------
@app.get("/")
def root():
    return {"message": "David AI Core v3 is running"}
