from fastapi import FastAPI
from pydantic import BaseModel
import hashlib
import json
import uuid
from datetime import datetime

app = FastAPI(title="David AI Core v5 - Trust Enforcement System")

# =========================================================
# CRYPTO LAYER (Integrity + Signing)
# =========================================================

class CryptoLayer:
    @staticmethod
    def hash(data: dict) -> str:
        encoded = json.dumps(data, sort_keys=True).encode()
        return hashlib.sha3_512(encoded).hexdigest()

    @staticmethod
    def sign_event(prev_hash: str, payload: dict) -> dict:
        envelope = {
            "prev_hash": prev_hash,
            "payload": payload,
            "timestamp": datetime.utcnow().isoformat()
        }
        envelope["hash"] = CryptoLayer.hash(envelope)
        return envelope


# =========================================================
# AUDIT LEDGER (Immutable Event Chain)
# =========================================================

class AuditLedger:
    def __init__(self):
        self.chain = []
        self.last_hash = "GENESIS"

    def record(self, event_type: str, data: dict):
        event = {
            "event": event_type,
            "data": data
        }

        signed = CryptoLayer.sign_event(self.last_hash, event)

        self.chain.append(signed)
        self.last_hash = signed["hash"]

        return signed


# =========================================================
# IDENTITY LAYER (Device Trust)
# =========================================================

class IdentityLayer:
    def verify(self, device_id: str, signature: str) -> bool:
        if not device_id or len(device_id) < 4:
            return False
        return True  # placeholder for real key verification


# =========================================================
# RISK ENGINE (Deterministic Scoring)
# =========================================================

class RiskEngine:
    def score(self, intent: str, context: dict) -> int:
        score = 0

        if context.get("untrusted_network"):
            score += 50

        if context.get("anomaly"):
            score += 40

        if "payment" in intent.lower():
            score += 20

        if context.get("privileged_action"):
            score += 30

        return min(score, 100)


# =========================================================
# POLICY ENGINE (Decision Authority)
# =========================================================

class PolicyEngine:
    def decide(self, risk: int) -> str:
        if risk >= 75:
            return "DENY"
        if risk >= 40:
            return "REVIEW"
        return "ALLOW"


# =========================================================
# CORE ORCHESTRATOR (THE TRUST GATE)
# =========================================================

class DavidCoreV5:
    def __init__(self):
        self.audit = AuditLedger()
        self.identity = IdentityLayer()
        self.risk = RiskEngine()
        self.policy = PolicyEngine()

    def execute(self, device_id: str, intent: str, context: dict):

        # 1. Identity Gate
        if not self.identity.verify(device_id, ""):
            event = self.audit.record("IDENTITY_FAIL", {
                "device_id": device_id
            })

            return self._response("BLOCKED", 100, event)

        # 2. Risk Evaluation
        risk = self.risk.score(intent, context)

        # 3. Policy Decision
        decision = self.policy.decide(risk)

        # 4. State Enforcement (fail-closed)
        state = "ACTIVE" if decision == "ALLOW" else "LOCKED"

        # 5. Audit Record
        event = self.audit.record("DECISION", {
            "device_id": device_id,
            "intent": intent,
            "risk": risk,
            "decision": decision,
            "state": state
        })

        return self._response(decision, risk, event, state)

    def _response(self, decision, risk, event, state="LOCKED"):
        return {
            "decision": decision,
            "risk_score": risk,
            "system_state": state,
            "audit_hash": event["hash"]
        }


# =========================================================
# GLOBAL INSTANCE
# =========================================================

core = DavidCoreV5()


# =========================================================
# API SCHEMA
# =========================================================

class RequestModel(BaseModel):
    device_id: str
    intent: str
    context: dict


# =========================================================
# MAIN EXECUTION PIPELINE
# =========================================================

@app.post("/process")
def process(req: RequestModel):
    return core.execute(req.device_id, req.intent, req.context)


@app.get("/audit")
def audit():
    return core.audit.chain


@app.get("/status")
def status():
    return {
        "system": "DAVID CORE v5",
        "events": len(core.audit.chain),
        "state": "OPERATIONAL"
    }


@app.get("/")
def root():
    return {"message": "David AI Core v5 online"}
