from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import os
from datetime import datetime

app = FastAPI()

RUNTIME_KEY = os.getenv("DAVID_RUNTIME_KEY", "change_me")

class EnforceRequest(BaseModel):
    actor_id: str
    action_type: str
    payload: dict

@app.get("/")
def health():
    return {"status": "DAVID ONLINE", "utc": datetime.utcnow().isoformat()}

@app.post("/v1/enforce")
def enforce(req: EnforceRequest, authorization: str = Header(None)):
    if authorization != f"Bearer {RUNTIME_KEY}":
        raise HTTPException(status_code=403, detail="DENY: bad or missing runtime key")

    # deny-by-default
    if req.action_type == "OUTPUT_TEXT":
        return {"decision": "ALLOW", "rule_applied": "R-ALLOW-OUTPUT_TEXT"}

    return {"decision": "DENY", "rule_applied": "R-DENY-DEFAULT"}
