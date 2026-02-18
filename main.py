from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from datetime import datetime
import os

app = FastAPI()

RUNTIME_KEY = os.getenv("RUNTIME_KEY", "david_rt_93jf82hf92hf82hf82hfi238hf")


class EnforceRequest(BaseModel):
    actor_id: str
    action_type: str
    payload: dict


@app.get("/")
def health():
    return {
        "status": "DAVID ONLINE",
        "utc": datetime.utcnow().isoformat()
    }


@app.post("/v1/enforce")
def enforce(req: EnforceRequest, authorization: str = Header(None)):

    if authorization != f"Bearer {RUNTIME_KEY}":
        raise HTTPException(status_code=403, detail="DENY: bad or missing runtime key")

    # ALLOW rule
    if req.action_type == "OUTPUT_TEXT":
        return {
            "decision": "ALLOW",
            "rule_applied": "R-OUTPUT-ALLOW"
        }

    # DENY by default
    return {
        "decision": "DENY",
        "rule_applied": "R-DENY-BY-DEFAULT"
    }
