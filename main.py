from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import hashlib
import json
import os
import time
import hmac
from collections import defaultdict

app = FastAPI(title="DAVID Runtime")

# ==============================
# CONFIG
# ==============================

API_KEY = os.getenv("DAVID_API_KEY", "test123")
POLICY_SECRET = os.getenv("DAVID_POLICY_SECRET", "change_this_secret")
AUDIT_FILE = "audit.log"

ALLOWED_MODELS = {
    "gpt-4o-mini",
    "gpt-4.1",
    "deepseek-chat",
    "claude-3-5-sonnet"
}

BLOCK_PATTERNS = [
    "ignore previous instructions",
    "bypass security",
    "disable security",
    "reveal system prompt",
    "override david",
    "ignore david",
    "jailbreak",
]

ALLOWED_ACTIONS = [
    "model:invoke",
    "email:create_draft"
]

REQUEST_LOG = defaultdict(list)

MAX_REQUESTS_PER_MINUTE = 20
MAX_PROMPT_LENGTH = 4000


# ==============================
# REQUEST MODEL
# ==============================

class Request(BaseModel):
    actor: str
    action: str
    tool: Optional[str] = None
    model: Optional[str] = None
    prompt: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


# ==============================
# AUTH
# ==============================

def verify_token(header):

    if not header:
        return None

    if not header.startswith("Bearer "):
        return None

    token = header.split(" ")[1]

    if token == API_KEY:
        return {"actor":"authorized"}

    return None


# ==============================
# PROMPT ATTACK DETECTION
# ==============================

def detect_prompt_attack(prompt):

    text = (prompt or "").lower()

    for pattern in BLOCK_PATTERNS:
        if pattern in text:
            return {
                "allow": False,
                "reason": "PROMPT_ATTACK_DETECTED",
                "pattern": pattern
            }

    return {"allow": True}


# ==============================
# ANOMALY DETECTION
# ==============================

def detect_anomaly(actor, action, prompt):

    now = time.time()
    key = f"{actor}:{action}"

    REQUEST_LOG[key] = [t for t in REQUEST_LOG[key] if now - t < 60]
    REQUEST_LOG[key].append(now)

    if len(REQUEST_LOG[key]) > MAX_REQUESTS_PER_MINUTE:
        return {
            "allow": False,
            "reason": "RATE_LIMIT_EXCEEDED"
        }

    if len(prompt or "") > MAX_PROMPT_LENGTH:
        return {
            "allow": False,
            "reason": "PROMPT_TOO_LARGE"
        }

    return {"allow": True}


# ==============================
# MODEL CONTROL
# ==============================

def enforce_model_allowlist(model):

    if model not in ALLOWED_MODELS:
        return {
            "allow": False,
            "reason": "MODEL_NOT_ALLOWED"
        }

    return {"allow": True}


# ==============================
# POLICY ENGINE
# ==============================

def evaluate_policy(req):

    if req.action not in ALLOWED_ACTIONS:
        return {
            "allow": False,
            "reason": "ACTION_NOT_ALLOWED"
        }

    return {
        "allow": True
    }


# ==============================
# AUDIT CHAIN
# ==============================

def last_hash():

    if not os.path.exists(AUDIT_FILE):
        return "GENESIS"

    with open(AUDIT_FILE,"r") as f:
        lines = f.readlines()

    if not lines:
        return "GENESIS"

    last = json.loads(lines[-1])

    return last["hash"]


def write_audit_event(request, decision):

    prev = last_hash()

    event = {
        "time": int(time.time()),
        "request": request,
        "decision": decision,
        "prev_hash": prev
    }

    raw = json.dumps(event,sort_keys=True).encode()

    event_hash = hashlib.sha256(raw).hexdigest()

    event["hash"] = event_hash

    with open(AUDIT_FILE,"a") as f:
        f.write(json.dumps(event)+"\n")


# ==============================
# API ENDPOINT
# ==============================

@app.get("/")
def root():
    return {"status":"DAVID running"}

@app.post("/v1/enforce")
def enforce(req: Request, authorization: str | None = Header(default=None)):

    actor = verify_token(authorization)

    if not actor:
        decision = {"allow":False,"reason":"AUTH_FAILED"}
        write_audit_event(req.dict(), decision)
        raise HTTPException(status_code=401, detail=decision)

    attack = detect_prompt_attack(req.prompt)
    if not attack["allow"]:
        write_audit_event(req.dict(), attack)
        raise HTTPException(status_code=403, detail=attack)

    anomaly = detect_anomaly(req.actor, req.action, req.prompt)
    if not anomaly["allow"]:
        write_audit_event(req.dict(), anomaly)
        raise HTTPException(status_code=429, detail=anomaly)

    model_check = enforce_model_allowlist(req.model)
    if not model_check["allow"]:
        write_audit_event(req.dict(), model_check)
        raise HTTPException(status_code=403, detail=model_check)

    decision = evaluate_policy(req)

    if not decision["allow"]:
        write_audit_event(req.dict(), decision)
        raise HTTPException(status_code=403, detail=decision)

    result = {
        "status":"allowed",
        "message":"Request passed David enforcement",
        "model": req.model
    }

    write_audit_event(req.dict(), result)

    return result
