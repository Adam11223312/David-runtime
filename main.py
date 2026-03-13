from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import hashlib
import json
import os
import time
import re
from collections import defaultdict

app = FastAPI(title="DAVID Runtime")

# ==============================
# CONFIG
# ==============================

API_KEY = os.getenv("DAVID_API_KEY", "test123")
AUDIT_FILE = "audit.log"

ALLOWED_MODELS = {
    "deepseek-chat",
    "gpt-4o-mini",
    "gpt-4.1",
    "claude-3-5-sonnet"
}

ALLOWED_ACTIONS = {
    "model:invoke",
    "email:create_draft"
}

ALLOWED_TOOLS = {
    "chat",
    "email"
}

REQUEST_LOG = defaultdict(list)

MAX_REQUESTS_PER_MINUTE = 20
MAX_PROMPT_LENGTH = 4000

BLOCK_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard previous instructions",
    "forget previous instructions",
    "bypass security",
    "disable security",
    "turn off security",
    "override security",
    "override david",
    "ignore david",
    "disable david",
    "jailbreak",
    "reveal system prompt",
    "reveal hidden prompt",
    "show system prompt",
    "print system prompt",
    "developer instructions",
    "system instructions",
    "admin instructions",
    "act as developer",
    "act as system",
    "pretend you are the developer",
    "pretend you are system",
    "ignore safety rules",
    "ignore safety policy",
    "turn off filters",
    "disable filters",
    "remove restrictions",
    "operate without restrictions",
    "bypass policy",
    "evade policy",
    "ignore policy",
    "do not follow policy",
    "exfiltrate",
    "steal credentials",
    "dump secrets",
    "reveal secrets",
    "show secrets",
    "print secrets",
    "export secrets",
    "leak data",
    "extract tokens",
    "show api key",
    "show private key",
    "execute shell",
    "run shell",
    "run command",
    "execute command",
    "spawn process",
    "privilege escalation",
    "escalate privileges",
    "admin override",
    "sudo",
    "rm rf",
    "curl http",
    "wget http",
    "base64 decode",
    "decode this payload",
    "remote code execution",
    "sql injection",
    "drop table",
    "union select"
]
BYPASS_VERBS = [
    "ignore",
    "bypass",
    "disable",
    "remove",
    "override",
    "evade",
    "skip",
    "avoid",
    "circumvent",
    "set aside",
    "disregard",
    "forget"
]

SAFETY_TERMS = [
    "safety",
    "rules",
    "policy",
    "policies",
    "safeguards",
    "framework",
    "restrictions",
    "filters",
    "controls",
    "guardrails"
]
DANGEROUS_TERM_GROUPS = [
    ["ignore", "instructions"],
    ["bypass", "security"],
    ["disable", "security"],
    ["reveal", "prompt"],
    ["system", "prompt"],
    ["developer", "instructions"],
    ["ignore", "policy"],
    ["remove", "restrictions"],
    ["without", "restrictions"],
    ["exfiltrate", "data"],
    ["steal", "credentials"],
    ["show", "api", "key"],
    ["private", "key"],
    ["execute", "command"],
    ["run", "shell"],
    ["privilege", "escalation"],
    ["sql", "injection"]
]

# ==============================
# REQUEST MODEL
# ==============================

class Request(BaseModel):
    actor: str
    action: str
    model: Optional[str] = None
    tool: Optional[str] = None
    prompt: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

# ==============================
# TEXT HELPERS
# ==============================

def remove_emojis(text: str) -> str:
    emoji_pattern = re.compile(
        "["
        "\U0001F600-\U0001F64F"
        "\U0001F300-\U0001F5FF"
        "\U0001F680-\U0001F6FF"
        "\U0001F700-\U0001F77F"
        "\U0001F780-\U0001F7FF"
        "\U0001F800-\U0001F8FF"
        "\U0001F900-\U0001F9FF"
        "\U0001FA00-\U0001FAFF"
        "\U00002702-\U000027B0"
        "\U000024C2-\U0001F251"
        "]+",
        flags=re.UNICODE
    )
    return emoji_pattern.sub(" ", text or "")

def normalize_text(text: str) -> str:
    text = remove_emojis(text or "")
    text = text.lower()
    text = re.sub(r"[_\-]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[^a-z0-9 ]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

def tokenize_text(text: str) -> list[str]:
    normalized = normalize_text(text)
    if not normalized:
        return []
    return normalized.split()

# ==============================
# AUTH
# ==============================

def verify_token(header):
    if not header:
        return None

    if not header.startswith("Bearer "):
        return None

    token = header.split(" ", 1)[1].strip()

    if token == API_KEY:
        return {"actor": "authorized"}

    return None

# ==============================
# PROMPT ATTACK DETECTION
# ==============================

def detect_prompt_attack(prompt):
    text = normalize_text(prompt or "")
    tokens = set(tokenize_text(prompt or ""))

    if not text:
        return {
            "allow": False,
            "reason": "EMPTY_PROMPT_FAIL_CLOSED"
        }

    for pattern in BLOCK_PATTERNS:
        normalized_pattern = normalize_text(pattern)
        if normalized_pattern in text:
            return {
                "allow": False,
                "reason": "PROMPT_ATTACK_DETECTED",
                "pattern": normalized_pattern
            }

    for group in DANGEROUS_TERM_GROUPS:
        normalized_group = [normalize_text(x) for x in group]
        if all(term in tokens for term in normalized_group):
            return {
                "allow": False,
                "reason": "DANGEROUS_TERM_COMBINATION",
                "pattern": " ".join(normalized_group)
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
# FAIL-CLOSED ALLOWLIST CHECKS
# ==============================

def enforce_action_allowlist(action):
    if not action:
        return {
            "allow": False,
            "reason": "ACTION_REQUIRED"
        }

    if action not in ALLOWED_ACTIONS:
        return {
            "allow": False,
            "reason": "ACTION_NOT_ALLOWED"
        }

    return {"allow": True}

def enforce_model_allowlist(model):
    if not model:
        return {
            "allow": False,
            "reason": "MODEL_REQUIRED"
        }

    if model not in ALLOWED_MODELS:
        return {
            "allow": False,
            "reason": "MODEL_NOT_ALLOWED"
        }

    return {"allow": True}

def enforce_tool_allowlist(tool):
    if tool is None:
        return {"allow": True}

    if tool not in ALLOWED_TOOLS:
        return {
            "allow": False,
            "reason": "TOOL_NOT_ALLOWED"
        }

    return {"allow": True}

# ==============================
# POLICY ENGINE
# ==============================

def evaluate_policy(req):
    allow_rules = [
        {
            "action": "model:invoke",
            "required_model": True
        },
        {
            "action": "email:create_draft",
            "required_tool": "email"
        }
    ]

    for rule in allow_rules:
        if req.action == rule["action"]:
            if rule.get("required_model") and not req.model:
                return {
                    "allow": False,
                    "reason": "MODEL_REQUIRED_BY_RULE"
                }

            if rule.get("required_tool") and req.tool != rule["required_tool"]:
                return {
                    "allow": False,
                    "reason": "RULE_TOOL_MISMATCH"
                }

            return {"allow": True}

    return {
        "allow": False,
        "reason": "DEFAULT_DENY_FAIL_CLOSED"
    }

# ==============================
# AUDIT CHAIN
# ==============================

def last_hash():
    if not os.path.exists(AUDIT_FILE):
        return "GENESIS"

    with open(AUDIT_FILE, "r", encoding="utf-8") as f:
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

    raw = json.dumps(event, sort_keys=True).encode()
    event_hash = hashlib.sha256(raw).hexdigest()
    event["hash"] = event_hash

    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

# ==============================
# API ENDPOINTS
# ==============================

@app.get("/")
def root():
    return {"status": "DAVID running"}

@app.post("/v1/enforce")
def enforce(req: Request, authorization: str | None = Header(default=None)):
    actor = verify_token(authorization)

    if not actor:
        decision = {"allow": False, "reason": "AUTH_FAILED"}
        write_audit_event(req.model_dump(), decision)
        raise HTTPException(status_code=401, detail=decision)

    action_check = enforce_action_allowlist(req.action)
    if not action_check["allow"]:
        write_audit_event(req.model_dump(), action_check)
        raise HTTPException(status_code=403, detail=action_check)

    model_check = enforce_model_allowlist(req.model)
    if not model_check["allow"]:
        write_audit_event(req.model_dump(), model_check)
        raise HTTPException(status_code=403, detail=model_check)

    tool_check = enforce_tool_allowlist(req.tool)
    if not tool_check["allow"]:
        write_audit_event(req.model_dump(), tool_check)
        raise HTTPException(status_code=403, detail=tool_check)

    attack_check = detect_prompt_attack(req.prompt)
    if not attack_check["allow"]:
        write_audit_event(req.model_dump(), attack_check)
        raise HTTPException(status_code=403, detail=attack_check)

    anomaly_check = detect_anomaly(req.actor, req.action, req.prompt)
    if not anomaly_check["allow"]:
        write_audit
