import os
import time
import json
import uuid
import hmac
import hashlib
from typing import Dict, Any, Optional
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse


app = FastAPI(title="David Security Gateway")


# =========================================================
# CONFIG
# =========================================================

APP_NAME = "David Security Gateway"
APP_MODE = "fail-closed"

TRUSTED_IPS = {
    ip.strip() for ip in os.getenv("TRUSTED_IPS", "").split(",") if ip.strip()
}

REQUIRE_DEVICE_PROOF = os.getenv("REQUIRE_DEVICE_PROOF", "true").lower() == "true"
DEVICE_PROOF_SECRET = os.getenv("DEVICE_PROOF_SECRET", "change-me-now")
DAVID_ADMIN_SECRET = os.getenv("DAVID_ADMIN_SECRET", "change-me-now-too")

RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "30"))

HIGH_RISK_THRESHOLD = int(os.getenv("HIGH_RISK_THRESHOLD", "5"))
TRANSFER_APPROVAL_THRESHOLD = float(os.getenv("TRANSFER_APPROVAL_THRESHOLD", "1000"))

ALLOWED_ENDPOINTS = {
    "/balance": ["user", "admin"],
    "/transfer": ["user", "admin"],
    "/admin/approve-transfer": ["admin"],
    "/admin/issue-token": ["admin"],
    "/admin/revoke-token": ["admin"],
    "/admin/pending-transfers": ["admin"],
}

# In production, move these stores to Redis/Postgres.
RATE_LIMIT_STORE: Dict[str, list] = {}
PENDING_TRANSFERS: Dict[str, Dict[str, Any]] = {}
REVOKED_TOKEN_HASHES = set()

# Token store keeps HASHED tokens only.
# Format:
# token_hash -> {role, expires, one_time, used, label}
TOKEN_STORE: Dict[str, Dict[str, Any]] = {}


# =========================================================
# HELPERS
# =========================================================

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utcnow().isoformat()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def safe_json_log(event: Dict[str, Any]) -> None:
    print(json.dumps(event, default=str))


def log_event(
    request_id: str,
    path: str,
    method: str,
    decision: str,
    reason: str,
    status_code: int,
    ip: str,
    role: Optional[str] = None,
    risk_score: int = 0,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    payload = {
        "timestamp": iso_now(),
        "request_id": request_id,
        "app": APP_NAME,
        "path": path,
        "method": method,
        "decision": decision,
        "reason": reason,
        "status_code": status_code,
        "ip": ip,
        "role": role,
        "risk_score": risk_score,
    }
    if extra:
        payload.update(extra)
    safe_json_log(payload)


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def check_rate_limit(ip: str) -> bool:
    now = time.time()
    if ip not in RATE_LIMIT_STORE:
        RATE_LIMIT_STORE[ip] = []

    RATE_LIMIT_STORE[ip] = [
        ts for ts in RATE_LIMIT_STORE[ip]
        if now - ts < RATE_LIMIT_WINDOW
    ]

    if len(RATE_LIMIT_STORE[ip]) >= RATE_LIMIT_MAX:
        return False

    RATE_LIMIT_STORE[ip].append(now)
    return True


def verify_device_proof(request: Request) -> bool:
    """
    Simple device proof:
    client sends header x-device-id and x-device-proof
    proof = HMAC_SHA256(DEVICE_PROOF_SECRET, device_id)
    """
    device_id = request.headers.get("x-device-id")
    device_proof = request.headers.get("x-device-proof")

    if not device_id or not device_proof:
        return False

    expected = hmac.new(
        DEVICE_PROOF_SECRET.encode("utf-8"),
        device_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, device_proof)


def make_token_record(
    role: str,
    ttl_minutes: int = 60,
    one_time: bool = False,
    label: str = ""
) -> Dict[str, Any]:
    raw_token = str(uuid.uuid4())
    token_hash = sha256_text(raw_token)
    expires = utcnow() + timedelta(minutes=ttl_minutes)

    TOKEN_STORE[token_hash] = {
        "role": role,
        "expires": expires,
        "one_time": one_time,
        "used": False,
        "label": label,
        "created_at": utcnow(),
    }

    return {
        "token": raw_token,  # only shown once
        "role": role,
        "expires": expires.isoformat(),
        "one_time": one_time,
        "label": label,
    }


def get_token_data(raw_token: str) -> Optional[Dict[str, Any]]:
    token_hash = sha256_text(raw_token)

    if token_hash in REVOKED_TOKEN_HASHES:
        return None

    return TOKEN_STORE.get(token_hash)


def revoke_token(raw_token: str) -> bool:
    token_hash = sha256_text(raw_token)
    if token_hash in TOKEN_STORE:
        REVOKED_TOKEN_HASHES.add(token_hash)
        return True
    return False


def compute_risk_score(request: Request, path: str, body: Any) -> int:
    risk = 0
    ip = client_ip(request)

    if ip not in TRUSTED_IPS and TRUSTED_IPS:
        risk += 2

    if path.startswith("/admin"):
        risk += 2

    user_agent = request.headers.get("user-agent", "")
    if not user_agent:
        risk += 1

    if REQUIRE_DEVICE_PROOF and not verify_device_proof(request):
        risk += 2

    if isinstance(body, dict):
        amount = body.get("amount")
        if isinstance(amount, (int, float)) and amount >= TRANSFER_APPROVAL_THRESHOLD:
            risk += 3

    return risk


async def read_json_safe(request: Request) -> Any:
    try:
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            return await request.json()
        return None
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed JSON")


# =========================================================
# BOOTSTRAP ADMIN TOKEN
# =========================================================

def bootstrap_admin_token() -> None:
    raw = os.getenv("DAVID_BOOTSTRAP_ADMIN_TOKEN", "").strip()
    if not raw:
        return

    token_hash = sha256_text(raw)
    TOKEN_STORE[token_hash] = {
        "role": "admin",
        "expires": utcnow() + timedelta(days=30),
        "one_time": False,
        "used": False,
        "label": "bootstrap-admin",
        "created_at": utcnow(),
    }


bootstrap_admin_token()


# =========================================================
# SECURITY CORE
# =========================================================

async def enforce_security(request: Request) -> Dict[str, Any]:
    request_id = str(uuid.uuid4())
    path = request.url.path
    method = request.method
    ip = client_ip(request)

    request.state.request_id = request_id

    # Public endpoints
    if path in ["/", "/health"]:
        return {
            "request_id": request_id,
            "role": None,
            "risk_score": 0,
            "token": None,
            "body": None,
        }

    # Rate limit first
    if not check_rate_limit(ip):
        log_event(
            request_id=request_id,
            path=path,
            method=method,
            decision="deny",
            reason="rate_limit",
            status_code=429,
            ip=ip,
        )
        raise HTTPException(status_code=429, detail="Too many requests")

    body = await read_json_safe(request)

    # Authorization required
    auth = request.headers.get("authorization")
    if not auth or not auth.startswith("Bearer "):
        log_event(
            request_id=request_id,
            path=path,
            method=method,
            decision="deny",
            reason="missing_auth",
            status_code=401,
            ip=ip,
        )
        raise HTTPException(status_code=401, detail="Unauthorized")

    raw_token = auth.split(" ", 1)[1].strip()
    token_data = get_token_data(raw_token)

    if not token_data:
        log_event(
            request_id=request_id,
            path=path,
            method=method,
            decision="deny",
            reason="invalid_or_revoked_token",
            status_code=403,
            ip=ip,
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    if utcnow() > token_data["expires"]:
        log_event(
            request_id=request_id,
            path=path,
            method=method,
            decision="deny",
            reason="token_expired",
            status_code=403,
            ip=ip,
            role=token_data["role"],
        )
        raise HTTPException(status_code=403, detail="Token expired")

    if token_data.get("one_time") and token_data.get("used"):
        log_event(
            request_id=request_id,
            path=path,
            method=method,
            decision="deny",
            reason="one_time_token_already_used",
            status_code=403,
            ip=ip,
            role=token_data["role"],
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    if path not in ALLOWED_ENDPOINTS:
        log_event(
            request_id=request_id,
            path=path,
            method=method,
            decision="deny",
            reason="unknown_endpoint",
            status_code=404,
            ip=ip,
            role=token_data["role"],
        )
        raise HTTPException(status_code=404, detail="Not Found")

    role = token_data["role"]

    if role not in ALLOWED_ENDPOINTS[path]:
        log_event(
            request_id=request_id,
            path=path,
            method=method,
            decision="deny",
            reason="role_denied",
            status_code=403,
            ip=ip,
            role=role,
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    risk_score = compute_risk_score(request, path, body)

    if path.startswith("/admin") and REQUIRE_DEVICE_PROOF and not verify_device_proof(request):
        log_event(
            request_id=request_id,
            path=path,
            method=method,
            decision="deny",
            reason="missing_or_invalid_device_proof",
            status_code=403,
            ip=ip,
            role=role,
            risk_score=risk_score,
        )
        raise HTTPException(status_code=403, detail="Device proof required")

    if risk_score >= HIGH_RISK_THRESHOLD and path != "/admin/approve-transfer":
        log_event(
            request_id=request_id,
            path=path,
            method=method,
            decision="deny",
            reason="high_risk_request",
            status_code=403,
            ip=ip,
            role=role,
            risk_score=risk_score,
        )
        raise HTTPException(status_code=403, detail="High risk request")

    if token_data.get("one_time"):
        token_data["used"] = True

    request.state.role = role
    request.state.risk_score = risk_score
    request.state.token_label = token_data.get("label", "")
    request.state.body = body

    log_event(
        request_id=request_id,
        path=path,
        method=method,
        decision="allow",
        reason="authorized",
        status_code=200,
        ip=ip,
        role=role,
        risk_score=risk_score,
    )

    return {
        "request_id": request_id,
        "role": role,
        "risk_score": risk_score,
        "token": raw_token,
        "body": body,
    }


# =========================================================
# MIDDLEWARE
# =========================================================

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    try:
        await enforce_security(request)
        response = await call_next(request)
        return response
    except HTTPException as e:
        return JSONResponse(status_code=e.status_code, content={"error": e.detail})
    except Exception:
        request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
        log_event(
            request_id=request_id,
            path=request.url.path,
            method=request.method,
            decision="deny",
            reason="internal_fail_closed",
            status_code=403,
            ip=client_ip(request),
        )
        return JSONResponse(status_code=403, content={"error": "Denied"})


# =========================================================
# PUBLIC ROUTES
# =========================================================

@app.get("/")
def root():
    return {
        "name": APP_NAME,
        "status": "active",
        "mode": APP_MODE,
    }


@app.get("/health")
def health():
    return {"status": "ok"}


# =========================================================
# PROTECTED USER ROUTES
# =========================================================

@app.get("/balance")
def balance(request: Request):
    return {
        "balance": "$5,000",
        "role": request.state.role,
        "risk_score": request.state.risk_score,
        "request_id": request.state.request_id,
    }


@app.post("/transfer")
def transfer(request: Request):
    body = request.state.body or {}
    amount = body.get("amount")
    destination = body.get("destination")

    if amount is None or destination is None:
        raise HTTPException(status_code=400, detail="amount and destination required")

    if not isinstance(amount, (int, float)) or amount <= 0:
        raise HTTPException(status_code=400, detail="invalid amount")

    # Dual approval for large transfers
    if amount >= TRANSFER_APPROVAL_THRESHOLD:
        transfer_id = str(uuid.uuid4())
        PENDING_TRANSFERS[transfer_id] = {
            "transfer_id": transfer_id,
            "amount": amount,
            "destination": destination,
            "requested_by_role": request.state.role,
            "requested_at": iso_now(),
            "status": "pending_admin_approval",
            "risk_score": request.state.risk_score,
            "request_id": request.state.request_id,
        }
        return {
            "status": "pending_admin_approval",
            "transfer_id": transfer_id,
            "amount": amount,
            "destination": destination,
            "request_id": request.state.request_id,
        }

    return {
        "status": "transfer_approved",
        "amount": amount,
        "destination": destination,
        "approved_by_role": request.state.role,
        "risk_score": request.state.risk_score,
        "request_id": request.state.request_id,
    }


# =========================================================
# ADMIN ROUTES
# =========================================================

@app.get("/admin/pending-transfers")
def pending_transfers(request: Request):
    return {
        "pending": list(PENDING_TRANSFERS.values()),
        "count": len(PENDING_TRANSFERS),
        "request_id": request.state.request_id,
    }


@app.post("/admin/approve-transfer")
def approve_transfer(request: Request):
    body = request.state.body or {}
    transfer_id = body.get("transfer_id")
    admin_secret = request.headers.get("x-admin-secret")

    if not transfer_id:
        raise HTTPException(status_code=400, detail="transfer_id required")

    if admin_secret != DAVID_ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Admin secret required")

    transfer = PENDING_TRANSFERS.get(transfer_id)
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")

    transfer["status"] = "approved"
    transfer["approved_at"] = iso_now()
    transfer["approved_by_role"] = request.state.role
    transfer["approval_request_id"] = request.state.request_id

    return {
        "status": "approved",
        "transfer": transfer,
        "request_id": request.state.request_id,
    }


@app.post("/admin/issue-token")
def issue_token(request: Request):
    body = request.state.body or {}
    role = body.get("role", "user")
    ttl_minutes = int(body.get("ttl_minutes", 60))
    one_time = bool(body.get("one_time", False))
    label = body.get("label", "")

    if role not in {"user", "admin"}:
        raise HTTPException(status_code=400, detail="Invalid role")

    if ttl_minutes < 1 or ttl_minutes > 43200:
        raise HTTPException(status_code=400, detail="Invalid ttl_minutes")

    token_record = make_token_record(
        role=role,
        ttl_minutes=ttl_minutes,
        one_time=one_time,
        label=label,
    )

    return {
        "issued": True,
        "token_record": token_record,
        "request_id": request.state.request_id,
    }


@app.post("/admin/revoke-token")
def admin_revoke_token(request: Request):
    body = request.state.body or {}
    raw_token = body.get("token")

    if not raw_token:
        raise HTTPException(status_code=400, detail="token required")

    success = revoke_token(raw_token)

    return {
        "revoked": success,
        "request_id": request.state.request_id,
    }
