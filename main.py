from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import secrets, time, asyncio

app = FastAPI(title="David AI Governance System")

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# --- In-memory stores ---
tokens = {}  # token: device_id
sessions = {}  # device_id: list of commands
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
    return tokens.get(token) == device_id

def log_action(device_id, command, reason, risk_score, result):
    audit_logs.append({
        "timestamp": time.time(),
        "device_id": device_id,
        "command": command,
        "reason": reason,
        "risk_score": risk_score,
        "result": result
    })

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
    <title>David AI Governance System</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500&display=swap" rel="stylesheet">
    <style>
        body { 
            font-family: 'Orbitron', monospace; 
            background: radial-gradient(circle at top, #000010, #000000); 
            color: #0ff; 
            margin: 0; 
            padding: 20px; 
        }
        h1, h2 { text-align: center; color: #0ff; text-shadow: 0 0 10px #0ff; }
        form { 
            max-width: 500px; 
            margin: 20px auto; 
            padding: 20px; 
            background: rgba(0,0,0,0.7); 
            border: 2px solid #0ff; 
            border-radius: 10px; 
        }
        input, button { 
            width: 100%; 
            padding: 10px; 
            margin: 5px 0; 
            border-radius: 5px; 
            border: 1px solid #0ff; 
            background: #111; 
            color: #0ff; 
            font-family: 'Orbitron', monospace;
        }
        button { 
            background: #0ff; 
            color: #000; 
            font-weight: bold; 
            cursor: pointer; 
        }
        #logs { 
            max-height: 300px; 
            overflow-y: scroll; 
            border: 2px solid #0ff; 
            padding: 10px; 
            background: #111; 
            border-radius: 10px; 
            font-family: 'Orbitron', monospace;
        }
        #voiceSphere {
            width: 120px; 
            height: 120px; 
            border-radius: 50%; 
            background: radial-gradient(circle at center, #0ff, #004); 
            margin: 20px auto; 
            box-shadow: 0 0 30px #0ff, 0 0 50px #0ff inset;
            animation: pulse 2s infinite;
            position: relative;
        }
        #voiceSphere::before, #voiceSphere::after {
            content: '';
            position: absolute;
            width: 100%; height: 100%;
            border-radius: 50%;
            top: 0; left: 0;
            box-shadow: 0 0 10px #f0f, 0 0 20px #0ff inset;
            animation: glitch 1s infinite linear alternate-reverse;
        }
        @keyframes pulse {
            0% { transform: scale(1); box-shadow: 0 0 30px #0ff, 0 0 50px #0ff inset; }
            50% { transform: scale(1.2); box-shadow: 0 0 50px #0ff, 0 0 70px #0ff inset; }
            100% { transform: scale(1); box-shadow: 0 0 30px #0ff, 0 0 50px #0ff inset; }
        }
        @keyframes glitch {
            0% { transform: translate(0,0) rotate(0deg); opacity:1; }
            25% { transform: translate(2px,-2px) rotate(1deg); opacity:0.8; }
            50% { transform: translate(-2px,2px) rotate(-1deg); opacity:0.9; }
            75% { transform: translate(1px,-1px) rotate(0.5deg); opacity:0.7; }
            100% { transform: translate(0,0) rotate(0deg); opacity:1; }
        }
    </style>
</head>
<body>
    <h1>David AI Governance System</h1>
    <div id="voiceSphere"></div>

    <h2>Command Console</h2>
    <form id="cmdForm">
        Token: <input type="text" id="token" placeholder="Paste your token here"><br>
        Device ID: <input type="text" id="device" placeholder="Your device ID"><br>
        Command: <input type="text" id="command" placeholder="Enter command"><br>
        Reason: <input type="text" id="reason" placeholder="Reason for command"><br>
        Risk Score: <input type="number" id="risk" min="0" max="100" placeholder="0-100"><br>
        <button type="submit">Send</button>
    </form>

    <h2>Audit Logs</h2>
    <div id="logs"></div>

    <script>
        const form = document.getElementById('cmdForm');
        const logsDiv = document.getElementById('logs');
        const sphere = document.getElementById('voiceSphere');

        form.addEventListener('submit', async e => {
            e.preventDefault();
            const riskInput = document.getElementById('risk').value;
            const riskScore = parseInt(riskInput);
            if (isNaN(riskScore)) {
                alert("Risk Score must be a number between 0 and 100");
                return;
            }
            const data = {
                token: document.getElementById('token').value.trim(),
                device_id: document.getElementById('device').value.trim(),
                command: document.getElementById('command').value.trim(),
                reason: document.getElementById('reason').value.trim(),
                risk_score: riskScore
            };
            try {
                const res = await fetch('/execute', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                const result = await res.json();
                logsDiv.innerHTML = `<pre>${JSON.stringify(result, null, 2)}</pre>` + logsDiv.innerHTML;

                if (result.status === "success") {
                    const utterance = new SpeechSynthesisUtterance(result.message);
                    utterance.lang = 'en-US';
                    utterance.pitch = 1.2;
                    utterance.rate = 1.0;
                    speechSynthesis.speak(utterance);

                    sphere.style.animation = 'pulse 1s infinite';
                    utterance.onend = () => { sphere.style.animation = 'pulse 2s infinite'; }
                }

            } catch (err) {
                alert("Error communicating with David: " + err);
            }
        });
    </script>
</body>
</html>
"""

# --- Command execution endpoint ---
@app.post("/execute")
async def execute(cmd: Command):
    if not verify_token(cmd.token, cmd.device_id):
        return JSONResponse({"status": "error", "message": "Invalid token/device"}, status_code=403)
    
    allowed, message = fail_closed(cmd)
    if not allowed:
        return {"status": "blocked", "message": message}

    # Store session
    session_ctx = sessions.get(cmd.device_id, [])
    session_ctx.append({"command": cmd.command, "reason": cmd.reason})
    sessions[cmd.device_id] = session_ctx

    # Log action
    log_action(cmd.device_id, cmd.command, cmd.reason, cmd.risk_score, "EXECUTED")

    return {"status": "success", "message": f"Command executed: {cmd.command}", "session_context": session_ctx}

# --- Token generation endpoint ---
@app.get("/generate_token/{device_id}")
async def get_token(device_id: str):
    token = generate_token(device_id)
    return {"token": token}

# --- Audit logs endpoint ---
@app.get("/audit")
async def get_audit():
    return {"audit_logs": audit_logs}
