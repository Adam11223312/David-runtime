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
# --- Allow Safe Output Rule ---
if req.action_type == "OUTPUT_TEXT":
    text = req.payload.get("text", "")

    if len(text) < 500:
        return {
            "decision": "ALLOW",
            "rule_applied": "R-ALLOW-SAFE-OUTPUT"
        }
    # Default fail-closed
    return {"decision": "DENY", "rule_applied": "R-DENY-BY-DEFAULT"}
