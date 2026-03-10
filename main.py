from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any
import json
import os
import time
import hmac
import hashlib
import base64

app = FastAPI()

API_KEY = os.getenv("DAVID_API_KEY", "change_me_now")
SIGNING_SECRET = os.getenv("DAVID_SIGNING_SECRET", "change_me_signing_secret_now")

USED_NONCES = set()
USED_EXECUTION_TOKENS = set()


class EnforceRequest(BaseModel):
    request_id: str
    actor_id: str
    action_type: str
    payload: Dict[str, Any] = {}


class ExecuteRequest(BaseModel):
    execution_token: Dict[str, Any]


def load_rules():
    with open("rules.json", "r") as f:
        return json.load(f)


def sign_data(data: str) -> str:
    sig = hmac.new(
        SIGNING_SECRET.encode(),
        data.encode(),
        hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(sig).decode()


def verify_signature(data: str, signature: str) -> bool:
    expected = sign_data(data)
    return hmac.compare_digest(expected, signature)


def make_nonce() -> str:
    return base64.urlsafe_b64encode(os.urandom(16)).decode()


def create_execution_token(req: EnforceRequest) -> Dict[str, Any]:
    token_data = {
        "request_id": req.request_id,
        "actor_id": req.actor_id,
        "action_type": req.action_type,
        "payload": req.payload,
        "timestamp": int(time.time()),
        "expires": int(time.time()) + 60,
        "nonce": make_nonce()
    }

    raw = json.dumps(token_data, sort_keys=True)
    token_data["signature"] = sign_data(raw)
    return token_data


@app.post("/v1/enforce")
async def enforce(req: EnforceRequest, authorization: Optional[str] = Header(None)):
    if authorization != f"Bearer {API_KEY}":
        raise HTTPException(status_code=403, detail="DENY: invalid API key")

    rules = load_rules()

    for rule in rules.get("rules", []):
        if (
            rule.get("action_type") == req.action_type
            and rule.get("actor_id") in ("*", req.actor_id)
        ):
            if req.action_type == "OUTPUT_TEXT":
                text = req.payload.get("text", "")
                if len(text) <= rule.get("max_text_length", 500):
                    return {
                        "decision": rule.get("effect", "ALLOW"),
                        "rule_applied": rule["rule_id"],
                        "execution_token": create_execution_token(req)
                    }
                return {
                    "decision": "DENY",
                    "rule_applied": "R-DENY-BY-DEFAULT"
                }

            if rule.get("effect") == "REVIEW":
                return {
                    "decision": "REVIEW",
                    "rule_applied": rule["rule_id"],
                    "message": "Human approval required before execution"
                }

            return {
                "decision": rule.get("effect", "ALLOW"),
                "rule_applied": rule["rule_id"],
                "execution_token": create_execution_token(req)
            }

    return {
        "decision": "DENY",
        "rule_applied": "R-DENY-BY-DEFAULT"
    }


@app.post("/v1/execute")
async def execute(req: ExecuteRequest, authorization: Optional[str] = Header(None)):
    if authorization != f"Bearer {API_KEY}":
        raise HTTPException(status_code=403, detail="DENY: invalid API key")

    token = req.execution_token.copy()
    signature = token.pop("signature", None)

    if not signature:
        raise HTTPException(status_code=403, detail="DENY: missing signature")

    raw = json.dumps(token, sort_keys=True)

    if not verify_signature(raw, signature):
        raise HTTPException(status_code=403, detail="DENY: invalid token signature")

    if int(time.time()) > token["expires"]:
        raise HTTPException(status_code=403, detail="DENY: token expired")

    if token["nonce"] in USED_NONCES:
        raise HTTPException(status_code=403, detail="DENY: replay detected (nonce already used)")

    if token["request_id"] in USED_EXECUTION_TOKENS:
        raise HTTPException(status_code=403, detail="DENY: replay detected (request already executed)")

    USED_NONCES.add(token["nonce"])
    USED_EXECUTION_TOKENS.add(token["request_id"])

    return {
        "decision": "EXECUTED",
        "request_id": token["request_id"],
        "action_type": token["action_type"],
        "message": "Execution token accepted exactly once"
    }
