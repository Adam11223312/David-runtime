from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any
import json

app = FastAPI()

API_KEY = "david_rt_93jf82hf92hf82hf82hfi238hf"


class EnforceRequest(BaseModel):
    request_id: str
    actor_id: str
    action_type: str
    payload: Dict[str, Any] = {}


def load_rules():
    with open("rules.json", "r") as f:
        return json.load(f)


@app.post("/v1/enforce")
async def enforce(req: EnforceRequest, authorization: Optional[str] = Header(None)):
    if authorization != f"Bearer {API_KEY}":
        raise HTTPException(status_code=403, detail="DENY: invalid API key")

    rules = load_rules()

    for rule in rules.get("rules", []):
        if rule.get("action_type") == req.action_type and rule.get("actor_id") in ("*", req.actor_id):

            if req.action_type == "OUTPUT_TEXT":
                text = req.payload.get("text", "")
                if len(text)
