from fastapi import FastAPI, Request, Header
from fastapi.responses import HTMLResponse, JSONResponse
from datetime import datetime, timedelta
import uuid
import hmac
import hashlib
import json

app = FastAPI()

# =========================
# CONFIG
# =========================
CORRECT_CODE = "DAVID123"
ADMIN_KEY = "adminsecure"
VALID_DEVICE_ID = "trusted-device-01"
DEVICE_SHARED_SECRET = "device-shared-secret"
TOKEN_TTL_SECONDS = 60
DUAL_AUTH_WINDOW_SECONDS = 120

# =========================
# STATE
# =========================
logs = []
active_tokens = {}
used_tokens = set()
dual_approvals = {}

# =========================
# HELPERS
# =========================
def now_utc() -> datetime:
    return datetime.utcnow()

def iso_now() -> str:
    return now_utc().strftime("%Y-%m-%d %H:%M:%S UTC")

def log_event(status: str, reason_code: str, risk_score: int, details: dict | None = None):
    entry = {
        "time": iso_now(),
        "status": status,
        "reason_code": reason_code,
        "risk_score": risk_score,
        "details": details or {}
    }
    logs.append(entry)
    if len(logs) > 500:
        logs.pop(0)

def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

def make_hmac(message: str, secret: str) -> str:
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

def build_device_message(device_id: str, nonce: str) -> str:
    return f"{device_id}:{nonce}"

def cleanup_expired_tokens():
    expired = []
    current = now_utc()
    for token, info in active_tokens.items():
        if info["expires_at"] < current:
            expired.append(token)
    for token in expired:
        del active_tokens[token]

def cleanup_expired_dual_approvals():
    expired = []
    current = now_utc()
    for tx_id, info in dual_approvals.items():
        if info["expires_at"] < current:
            expired.append(tx_id)
    for tx_id in expired:
        del dual_approvals[tx_id]

def compute_risk(
    has_token: bool,
    token_valid: bool,
    token_reused: bool,
    device_ok: bool,
    code_ok: bool,
    biometric_ok: bool,
    transaction_type: str
) -> int:
    risk = 0

    if not has_token:
        risk += 35
    if not token_valid:
        risk += 25
    if token_reused:
        risk += 30
    if not device_ok:
        risk += 20
    if not code_ok:
        risk += 15
    if not biometric_ok:
        risk += 10

    if transaction_type == "medium":
        risk += 10
    elif transaction_type == "high":
        risk += 25

    return min(risk, 100)

def requires_dual_auth(transaction_type: str) -> bool:
    return transaction_type == "high"

def validate_device_proof(device_id: str | None, nonce: str | None, device_signature: str | None) -> bool:
    if not device_id or not nonce or not device_signature:
        return False
    if device_id != VALID_DEVICE_ID:
        return False
    expected = make_hmac(build_device_message(device_id, nonce), DEVICE_SHARED_SECRET)
    return hmac.compare_digest(expected, device_signature)

def validate_biometric(biometric: str | None) -> bool:
    # Demo enforcement. Replace with real biometric attestation later.
    return biometric == "verified"

def get_reason_for_denial(
    has_token: bool,
    token_reused: bool,
    token_valid: bool,
    device_ok: bool,
    code_ok: bool,
    biometric_ok: bool,
    dual_ok: bool,
    transaction_type: str
) -> str:
    if not has_token:
        return "NO_TOKEN"
    if token_reused:
        return "TOKEN_REUSED"
    if not token_valid:
        return "INVALID_OR_EXPIRED_TOKEN"
    if not device_ok:
        return "DEVICE_PROOF_FAILED"
    if not code_ok:
        return "WRONG_CODE"
    if not biometric_ok:
        return "BIOMETRIC_FAILED"
    if requires_dual_auth(transaction_type) and not dual_ok:
        return "DUAL_AUTH_REQUIRED"
    return "UNKNOWN_DENIAL"

# =========================
# UI
# =========================
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>David Security System</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <style>
            body {
                margin: 0;
                font-family: Arial, sans-serif;
                background: #05070a;
                color: #00ff88;
                text-align: center;
            }
            .wrap {
                max-width: 900px;
                margin: 0 auto;
                padding: 20px;
            }
            .card {
                background: #0d1117;
                border: 1px solid #1f2937;
                border-radius: 16px;
                padding: 20px;
                box-shadow: 0 0 20px rgba(0,255,136,0.08);
            }
            h1 { margin-bottom: 8px; }
            .sub { color: #9ca3af; margin-bottom: 18px; }
            .status {
                display: flex;
                justify-content: center;
                gap: 10px;
                flex-wrap: wrap;
                margin-bottom: 18px;
            }
            .pill {
                border: 1px solid #00ff88;
                border-radius: 999px;
                padding: 8px 14px;
                font-size: 14px;
            }
            input, select {
                width: 92%;
                max-width: 500px;
                padding: 14px;
                font-size: 20px;
                text-align: center;
                color: #00ff88;
                background: black;
                border: 1px solid #00ff88;
                border-radius: 10px;
                margin-bottom: 12px;
            }
            .row {
                display: flex;
                justify-content: center;
                gap: 12px;
                flex-wrap: wrap;
                margin-bottom: 12px;
            }
            button {
                background: #111827;
                color: #00ff88;
                border: 1px solid #00ff88;
                border-radius: 10px;
                padding: 12px 14px;
                margin: 4px;
                font-size: 16px;
                min-width: 60px;
                cursor: pointer;
            }
            button:hover {
                background: #0b1220;
            }
            .wide {
                min-width: 150px;
            }
            .result {
                margin-top: 18px;
                font-size: 24px;
                min-height: 32px;
            }
            .logs {
                text-align: left;
                margin-top: 20px;
                border: 1px solid #00ff88;
                border-radius: 12px;
                padding: 14px;
                max-height: 260px;
                overflow-y: auto;
                font-size: 12px;
                background: #020406;
            }
            .keygrid {
                max-width: 520px;
                margin: 0 auto 16px auto;
            }
            .small {
                color: #9ca3af;
                font-size: 13px;
                margin-bottom: 10px;
            }
        </style>
    </head>
    <body>
        <div class="wrap">
            <div class="card">
                <h1>DAVID SECURITY SYSTEM</h1>
                <div class="sub">Adaptive fail-closed security with token rotation, device proof, biometrics, risk scoring, and dual authorization</div>

                <div class="status">
                    <div class="pill">STATUS: ACTIVE</div>
                    <div class="pill">MODE: FAIL-CLOSED</div>
                    <div class="pill">TOKEN: SINGLE USE</div>
                    <div class="pill">DUAL AUTH: STEP-UP</div>
                </div>

                <input id="codeBox" placeholder="Enter code..." readonly />
                <div class="keygrid" id="keyboard"></div>

                <div class="row">
                    <select id="txnType">
                        <option value="low">LOW RISK</option>
                        <option value="medium">MEDIUM RISK</option>
                        <option value="high">HIGH RISK</option>
                    </select>
                </div>

                <div class="row">
                    <button class="wide" onclick="setBiometric('verified')">BIOMETRIC OK</button>
                    <button class="wide" onclick="setBiometric('failed')">BIOMETRIC FAIL</button>
                    <button class="wide" onclick="approveDual()">2ND APPROVAL</button>
                </div>

                <div class="row">
                    <button class="wide" onclick="submitCode()">ENTER</button>
                    <button class="wide" onclick="clearCode()">CLEAR</button>
                    <button class="wide" onclick="simulateAttack()">ATTACK</button>
                </div>

                <div class="small" id="metaBox">Biometric: not set | Dual approval: pending</div>
                <div class="result" id="resultBox"></div>

                <div class="logs" id="logsBox">Loading logs...</div>
            </div>
        </div>

        <script>
            const keys = "1234567890QWERTYUIOPASDFGHJKLZXCVBNM";
            const keyboard = document.getElementById("keyboard");
            const codeBox = document.getElementById("codeBox");
            const resultBox = document.getElementById("resultBox");
            const logsBox = document.getElementById("logsBox");
            const metaBox = document.getElementById("metaBox");

            let biometricState = "failed";
            let dualApproved = false;

            keys.split("").forEach(k => {
                const btn = document.createElement("button");
                btn.textContent = k;
                btn.onclick = () => codeBox.value += k;
                keyboard.appendChild(btn);
            });

            function clearCode() {
                codeBox.value = "";
                resultBox.textContent = "";
            }

            function setBiometric(value) {
                biometricState = value;
                updateMeta();
            }

            function updateMeta() {
                metaBox.textContent = `Biometric: ${biometricState} | Dual approval: ${dualApproved ? "approved" : "pending"}`;
            }

            async function getToken() {
                const r = await fetch("/token");
                return await r.json();
            }

            async function approveDual() {
                const txId = crypto.randomUUID();
                const body = {
                    tx_id: txId,
                    approver_1: "primary-user",
                    approver_2: "secondary-user",
                    device_1: "trusted-device-01",
                    device_2: "trusted-device-02"
                };

                const r = await fetch("/dual-approve", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify(body)
                });

                const data = await r.json();
                if (data.status === "approved") {
                    window.currentTxId = txId;
                    dualApproved = true;
                    resultBox.style.color = "#00ff88";
                    resultBox.textContent = "DUAL APPROVAL RECORDED";
                } else {
                    resultBox.style.color = "orange";
                    resultBox.textContent = "DUAL APPROVAL FAILED";
                }
                updateMeta();
                loadLogs();
            }

            async function submitCode() {
                const txnType = document.getElementById("txnType").value;
                const tokenResp = await getToken();

                const deviceId = tokenResp.device_id;
                const nonce = tokenResp.nonce;
                const signature = tokenResp.device_signature;
                const token = tokenResp.token;

                const payload = {
                    code: codeBox.value,
                    transaction_type: txnType,
                    biometric: biometricState,
                    tx_id: txnType === "high" ? (window.currentTxId || "") : ""
                };

                const r = await fetch("/validate", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + token,
                        "X-Device-ID": deviceId,
                        "X-Device-Nonce": nonce,
                        "X-Device-Signature": signature
                    },
                    body: JSON.stringify(payload)
                });

                const data = await r.json();

                if (data.status === "allowed") {
                    resultBox.style.color = "#00ff88";
                    resultBox.textContent = "ACCESS GRANTED";
                } else {
                    resultBox.style.color = "red";
                    resultBox.textContent = "ACCESS DENIED: " + (data.reason_code || "UNKNOWN");
                }

                if (txnType === "high") {
                    dualApproved = false;
                    window.currentTxId = "";
                    updateMeta();
                }

                await loadLogs();
            }

            async function simulateAttack() {
                const r = await fetch("/attack");
                const data = await r.json();
                resultBox.style.color = "orange";
                resultBox.textContent = "ATTACK BLOCKED: " + data.reason_code;
                await loadLogs();
            }

            async function loadLogs() {
                const r = await fetch("/logs");
                const data = await r.json();
                logsBox.innerHTML = "";

                const items = [...data.logs].reverse();
                if (!items.length) {
                    logsBox.textContent = "No logs yet.";
                    return;
                }

                items.forEach(l => {
                    const line = document.createElement("div");
                    line.style.marginBottom = "8px";
                    line.textContent = `${l.time} | ${l.status} | ${l.reason_code} | risk=${l.risk_score}`;
                    logsBox.appendChild(line);
                });
            }

            updateMeta();
            loadLogs();
        </script>
    </body>
    </html>
    """

# =========================
# TOKEN ISSUANCE
# =========================
@app.get("/token")
def generate_token():
    cleanup_expired_tokens()

    token = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    device_id = VALID_DEVICE_ID
    device_signature = make_hmac(build_device_message(device_id, nonce), DEVICE_SHARED_SECRET)

    active_tokens[token] = {
        "issued_at": now_utc(),
        "expires_at": now_utc() + timedelta(seconds=TOKEN_TTL_SECONDS),
        "device_id": device_id,
        "nonce": nonce,
        "used": False,
        "token_hash": sha256_hex(token)
    }

    log_event(
        "INFO",
        "TOKEN_ISSUED",
        0,
        {"token_hash": active_tokens[token]["token_hash"], "device_id": device_id}
    )

    return {
        "token": token,
        "expires_in_seconds": TOKEN_TTL_SECONDS,
        "device_id": device_id,
        "nonce": nonce,
        "device_signature": device_signature
    }

# =========================
# DUAL AUTH
# =========================
@app.post("/dual-approve")
async def dual_approve(request: Request):
    cleanup_expired_dual_approvals()

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"status": "blocked", "reason_code": "BAD_JSON"}, status_code=400)

    tx_id = data.get("tx_id", "").strip()
    approver_1 = data.get("approver_1", "").strip()
    approver_2 = data.get("approver_2", "").strip()
    device_1 = data.get("device_1", "").strip()
    device_2 = data.get("device_2", "").strip()

    if not tx_id or not approver_1 or not approver_2 or not device_1 or not device_2:
        log_event("DENIED", "DUAL_AUTH_BAD_REQUEST", 80, {"tx_id": tx_id})
        return JSONResponse({"status": "blocked", "reason_code": "DUAL_AUTH_BAD_REQUEST"}, status_code=400)

    if approver_1 == approver_2:
        log_event("DENIED", "DUAL_AUTH_SAME_APPROVER", 90, {"tx_id": tx_id})
        return JSONResponse({"status": "blocked", "reason_code": "DUAL_AUTH_SAME_APPROVER"}, status_code=403)

    if device_1 == device_2:
        log_event("DENIED", "DUAL_AUTH_SAME_DEVICE", 90, {"tx_id": tx_id})
        return JSONResponse({"status": "blocked", "reason_code": "DUAL_AUTH_SAME_DEVICE"}, status_code=403)

    dual_approvals[tx_id] = {
        "approved": True,
        "approver_1": approver_1,
        "approver_2": approver_2,
        "device_1": device_1,
        "device_2": device_2,
        "expires_at": now_utc() + timedelta(seconds=DUAL_AUTH_WINDOW_SECONDS)
    }

    log_event(
        "INFO",
        "DUAL_AUTH_APPROVED",
        0,
        {"tx_id": tx_id, "approver_1": approver_1, "approver_2": approver_2}
    )

    return {"status": "approved", "tx_id": tx_id}

# =========================
# VALIDATION
# =========================
@app.post("/validate")
async def validate(
    request: Request,
    authorization: str | None = Header(None),
    x_device_id: str | None = Header(None),
    x_device_nonce: str | None = Header(None),
    x_device_signature: str | None = Header(None)
):
    cleanup_expired_tokens()
    cleanup_expired_dual_approvals()

    try:
        data = await request.json()
    except Exception:
        log_event("DENIED", "BAD_JSON", 95, {})
        return JSONResponse({"status": "blocked", "reason_code": "BAD_JSON"}, status_code=400)

    code = str(data.get("code", ""))
    transaction_type = str(data.get("transaction_type", "low")).lower()
    biometric = data.get("biometric")
    tx_id = str(data.get("tx_id", ""))

    if transaction_type not in {"low", "medium", "high"}:
        transaction_type = "low"

    has_token = authorization is not None and authorization.startswith("Bearer ")
    token = authorization.replace("Bearer ", "", 1) if has_token else ""
    token_reused = token in used_tokens
    token_info = active_tokens.get(token)
    token_valid = token_info is not None and not token_reused

    device_ok = validate_device_proof(x_device_id, x_device_nonce, x_device_signature)
    code_ok = (code == CORRECT_CODE)
    biometric_ok = validate_biometric(biometric)

    dual_ok = True
    if requires_dual_auth(transaction_type):
        approval = dual_approvals.get(tx_id)
        dual_ok = bool(tx_id and approval and approval.get("approved") and approval.get("expires_at") > now_utc())

    risk = compute_risk(
        has_token=has_token,
        token_valid=token_valid,
        token_reused=token_reused,
        device_ok=device_ok,
        code_ok=code_ok,
        biometric_ok=biometric_ok,
        transaction_type=transaction_type
    )

    if requires_dual_auth(transaction_type) and not dual_ok:
        risk = min(100, risk + 20)

    if not (has_token and token_valid and not token_reused and device_ok and code_ok and biometric_ok and dual_ok):
        reason = get_reason_for_denial(
            has_token=has_token,
            token_reused=token_reused,
            token_valid=token_valid,
            device_ok=device_ok,
            code_ok=code_ok,
            biometric_ok=biometric_ok,
            dual_ok=dual_ok,
            transaction_type=transaction_type
        )
        log_event(
            "DENIED",
            reason,
            risk,
            {
                "transaction_type": transaction_type,
                "device_id": x_device_id,
                "tx_id": tx_id
            }
        )
        return JSONResponse(
            {
                "status": "blocked",
                "reason_code": reason,
                "risk_score": risk
            },
            status_code=403
        )

    used_tokens.add(token)
    if token in active_tokens:
        del active_tokens[token]

    if requires_dual_auth(transaction_type) and tx_id in dual_approvals:
        del dual_approvals[tx_id]

    log_event(
        "ALLOWED",
        "VERIFIED",
        0,
        {
            "transaction_type": transaction_type,
            "device_id": x_device_id,
            "tx_id": tx_id
        }
    )

    return {
        "status": "allowed",
        "reason_code": "VERIFIED",
        "risk_score": 0
    }

# =========================
# ATTACK SIMULATION
# =========================
@app.get("/attack")
def attack():
    log_event("DENIED", "SIMULATED_ATTACK", 98, {"mode": "fail_closed"})
    return {"status": "blocked", "reason_code": "SIMULATED_ATTACK", "risk_score": 98}

# =========================
# LOGS
# =========================
@app.get("/logs")
def get_logs():
    return {"logs": logs}

# =========================
# ADMIN
# =========================
@app.get("/admin")
def admin(key: str):
    if key != ADMIN_KEY:
        log_event("DENIED", "ADMIN_UNAUTHORIZED", 90, {})
        return JSONResponse({"status": "blocked", "reason_code": "ADMIN_UNAUTHORIZED"}, status_code=403)

    cleanup_expired_tokens()
    cleanup_expired_dual_approvals()

    return {
        "status": "ok",
        "active_token_count": len(active_tokens),
        "used_token_count": len(used_tokens),
        "pending_dual_approvals": list(dual_approvals.keys()),
        "recent_logs": logs[-20:]
    }
