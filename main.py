from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import os
import re

app = FastAPI(title="David Runtime", version="1.0")

API_KEY = os.getenv("API_KEY")

class EnforcementRequest(BaseModel):
    input: str

BLOCK_PATTERNS = [
    r"ignore previous instructions",
    r"reveal system prompt",
    r"print.*api key",
    r"developer mode",
    r"disable safety",
    r"expose secrets",
    r"bypass security",
]

def is_malicious(text: str):
    text = text.lower()
    for pattern in BLOCK_PATTERNS:
        if re.search(pattern, text):
            return True
    return False


@app.post("/v1/enforce")
async def enforce(req: EnforcementRequest, request: Request):

    auth = request.headers.get("authorization")

    if not auth or auth != f"Bearer {API_KEY}":
        raise HTTPException(status_code=401, detail="Unauthorized")

    if is_malicious(req.input):
        return {"decision": "BLOCK"}

    return {"decision": "ALLOW"}


@app.get("/")
def health():
    return {"status": "David runtime online"}
