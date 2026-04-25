from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import hashlib
import json
import uuid
from datetime import datetime

app = FastAPI(title="David AI Core - Orchestrator v5")

# -----------------------------
# CORE SYSTEM MODULES
# -----------------------------

class AuditChain:
    def __init__(self):
        self.chain = []
        self.last_hash = "GENESIS"

    def add(self, event_type, data):
        timestamp = datetime.utcnow().isoformat()

        payload = {
            "timestamp": timestamp,
            "event": event_type,
            "data": data,
            "prev_hash": self.last_hash
        }

        raw = json.dumps(payload, sort_keys=True).encode()
        current_hash = hashlib.sha256(raw).hexdigest()

        payload["hash"] = current_hash

        self.chain.append(payload)
        self.last_hash = current_hash

        return payload


class DecisionEngine:
    def evaluate(self, intent, risk_score):
        if risk_score >= 70:
            return "DENY"
        elif risk_score >= 40:
            return "REVIEW"
        return "ALLOW"


class RiskEngine:
    def score(self, intent, data):
        score = 0

        if data.get("unauthorized_access"):
            score += 60

        if "payment" in intent.lower():
            score += 20

        if data.get("anomaly"):
            score += 30

        return min(score, 100)


class QRSystem:
    def generate(self, state_hash, status):
        token = str(uuid.uuid4())[:8]
        return f"DAVID-{status}-{token}-{state_hash[:10]}"


# -----------------------------
# GLOBAL SYSTEM INSTANCE
# -----------------------------
audit = AuditChain()
risk_engine = RiskEngine()
decision_engine = DecisionEngine()
qr_system = QRSystem()

# -----------------------------
# API MODELS
# -----------------------------
class RequestPayload(BaseModel):
    device_id: str
    intent: str
    data: dict

# -----------------------------
# CORE PIPELINE (THIS IS DAVID)
# -----------------------------
@app.post("/process")
def process(req: RequestPayload):

    # 1. Risk
    risk = risk_engine.score(req.intent, req.data)

    # 2. Decision
    decision = decision_engine.evaluate(req.intent, risk)

    # 3. ENFORCEMENT (fail-closed)
    if decision == "DENY":
        status = "LOCKED"
    else:
        status = "ACTIVE"

    # 4. Audit log
    entry = audit.add("DECISION", {
        "device_id": req.device_id,
        "intent": req.intent,
        "risk": risk,
        "decision": decision,
        "status": status
    })

    # 5. State hash for QR
    state_hash = entry["hash"]
    qr = qr_system.generate(state_hash, status)

    # 6. Response
    return {
        "decision": decision,
        "risk": risk,
        "system_status": status,
        "qr_state": qr,
        "audit_hash": state_hash
    }


# -----------------------------
# AUDIT VIEW
# -----------------------------
@app.get("/audit")
def get_audit():
    return audit.chain


# -----------------------------
# SYSTEM CHECK
# -----------------------------
@app.get("/status")
def status():
    return {
        "system": "DAVID CORE v5",
        "state": "ONLINE",
        "entries": len(audit.chain)
    }
