from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any

app = FastAPI()

API_KEY = "david_rt_93jf82hf92hf82hf82hfi238hf"

class EnforceRequest(BaseModel):
    actor_id: str
    action_type: str
    payload: Dict[str, Any] = {}

@app.post("/v1/enforce")
async def enforce(req: EnforceRequest, authorization: Optional[str] = Header(None)):
    # AUTH
    if authorization != f"Bearer {API_KEY}":
        raise HTTPException(status_code=403, detail="DENY: bad or missing runtime key")

    # Example allow rule
    if req.actor_id == "admin" and req.action_type == "READ_STATUS":
        return {"decision": "ALLOW", "rule_applied": "R-ADMIN-ALLOW-SAFE"}

    # Default fail-closed
    return {"decision": "DENY", "rule_applied": "R-DENY-BY-DEFAULT"}
