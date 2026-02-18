from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import os
from datetime import datetime

app = FastAPI()

# Get the runtime key from environment variable
RUNTIME_KEY = os.getenv("DAVID_RUNTIME_KEY")

if not RUNTIME_KEY:
    raise RuntimeError("DAVID_RUNTIME_KEY not set")

# Request body model
class EnforceRequest(BaseModel):
    actor_id: str
    action_type: str
    payload: dict

# Health check endpoint
@app.get("/")
def health():
    return {"status": "DAVID ONLINE", "utc": datetime.utcnow().isoformat()}

# Enforcement endpoint
@app.post("/v1/enforce")
def enforce(req: EnforceRequest, authorization: str = Header(None)):
    if authorization != f"Bearer {RUNTIME_KEY}":
        raise HTTPException(status_code=403, detail="DENY: bad or missing runtime key")

    # deny-by-default
    if req.action_type == "OUTPUT_TEXT":
        print({
            "timestamp": datetime.utcnow().isoformat(),
            "actor": req.actor_id,
            "action": req.action_type,
            "decision": "ALLOW"
        })
        return {"decision": "ALLOW", "rule_applied": "R-ALLOW-OUTPUT_TEXT"}

    print({
        "timestamp": datetime.utcnow().isoformat(),
        "actor": req.actor_id,
        "action": req.action_type,
        "decision": "DENY"
    })
    return {"decision": "DENY", "rule_applied": "R-DENY-DEFAULT"}

