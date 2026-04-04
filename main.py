# main.py
from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import secrets, time, asyncio

app = FastAPI(title="David AI Governance System")

# --- CORS for UI ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # adjust for deployment
    allow_methods=["*"],
    allow_headers=["*"]
)

# --- In-memory stores ---
tokens = {}  # token: device_id
device_proofs = {}  # device_id: proof
sessions = {}  # session_id: context
audit_logs = []  # list of dicts
risk_threshold = 70  # 0-100

# --- Models ---
class Command(BaseModel):
    token: str
    device_id: str
    command: str
    reason: str
    risk_score: int

# --- Helpers ---
def generate_token(device_id):
    token = secrets.token_hex(16)
    tokens[token] = device_id
    return token

def verify_token(token, device_id):
    valid_device = tokens.get(token)
    if valid_device != device_id:
        return False
    return True

def log_action(device_id, command, reason, risk_score, result):
    log_entry = {
        "timestamp": time.time(),
        "device_id": device_id,
        "command": command,
        "reason": reason,
        "risk_score": risk_score,
        "result": result
    }
    audit_logs.append(log_entry)

def fail_closed(command_obj: Command):
    if command_obj.risk_score > risk_threshold:
        log_action(command_obj.device_id, command_obj.command,
                   command_obj.reason, command_obj.risk_score, "BLOCKED")
        return False, "Blocked due to high risk"
    return True, "Allowed"

# --- Routes ---
@app.get("/", response_class=HTMLResponse)
async def ui():
    return """
    <html>
    <head>
        <title>David AI Governance UI</title>
        <style>
            body { font-family: Arial; margin: 20px; }
            #logs { max-height: 300px; overflow-y: scroll; border: 1px solid #ccc; padding: 10px; }
        </style>
    </head>
    <body>
        <h1>David AI Governance System</h1>
        <h2>Command Console</h2>
        <form id="cmdForm">
            Token: <input type="text" id="token"><br>
            Device ID: <input type="text" id="device"><br>
            Command: <input type="text" id="command"><br>
            Reason: <input type="text" id="reason"><br>
            Risk Score: <input type="number" id="risk" min="0" max="100"><br>
            <button type="submit">Send</button>
        </form>
        <h2>Audit Logs</h2>
        <div id="logs"></div>
        <script>
            const form = document.getElementById('cmdForm');
            const logsDiv = document.getElementById('logs');
            form.addEventListener('submit', async e => {
                e.preventDefault();
                const data = {
                    token: document.getElementById('token').value,
                    device_id: document.getElementById('device').value,
                    command: document.getElementById('command').value,
                    reason: document.getElementById('reason').value,
                    risk_score: parseInt(document.getElementById('risk').value)
                };
                const res = await fetch('/execute', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                const result = await res.json();
                logsDiv.innerHTML = `<pre>${JSON.stringify(result, null, 2)}</pre>` + logsDiv.innerHTML;
            });
        </script>
    </body>
    </html>
    """

@app.post("/execute")
async def execute(cmd: Command):
    # Verify token & device
    if not verify_token(cmd.token, cmd.device_id):
        return JSONResponse({"status": "error", "message": "Invalid token/device"}, status_code=403)
    
    # Fail-closed check
    allowed, message = fail_closed(cmd)
    if not allowed:
        return {"status": "blocked", "message": message}

    # Simulate command execution & session context
    session_ctx = sessions.get(cmd.device_id, [])
    session_ctx.append({"command": cmd.command, "reason": cmd.reason})
    sessions[cmd.device_id] = session_ctx

    # Log successful action
    log_action(cmd.device_id, cmd.command, cmd.reason, cmd.risk_score, "EXECUTED")
    return {"status": "success", "message": f"Command executed: {cmd.command}", "session_context": session_ctx}

@app.get("/generate_token/{device_id}")
async def get_token(device_id: str):
    token = generate_token(device_id)
    # Simulate rotating device proof
    device_proofs[device_id] = secrets.token_hex(8)
    return {"token": token, "device_proof": device_proofs[device_id]}

@app.get("/audit")
async def get_audit():
    return {"audit_logs": audit_logs}

# --- Background stress simulation ---
async def stress_simulator():
    while True:
        if tokens:
            device_id = list(tokens.values())[0]
            cmd = Command(
                token=list(tokens.keys())[0],
                device_id=device_id,
                command="stress_test",
                reason="background",
                risk_score=10
            )
            await execute(cmd)
        await asyncio.sleep(5)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(stress_simulator())
