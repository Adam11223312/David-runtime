from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps
import os

# ========================
# Auth decorator
# =========================
def require_auth(admin_only=False):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                auth = request.headers.get("Authorization", "")
                if not auth.startswith("Bearer "):
                    return jsonify({"error": "Unauthorized"}), 401
                token = auth.split(" ")[1]
                payload = validate_token(token)
                if not payload:
                    return jsonify({"error": "Invalid token"}), 403
                if admin_only and payload.get("role") != "admin":
                    return jsonify({"error": "Admin only"}), 403
                return f(payload, *args, **kwargs)
            except Exception as e:
                print("[AUTH ERROR]", e)
                return jsonify({"error": "Auth failure"}), 500
        return wrapper
    return decorator

# =========================
# Routes
# =========================
@app.route("/")
def home():
    return "David Running"

@app.route("/token/<user>/<role>")
def token(user, role):
    return jsonify({"token": generate_token(user, role)})

@app.route("/admin")
@require_auth(admin_only=True)
def admin(payload):
    return jsonify({
        "status": "admin ok",
        "user": payload.get("user_id")
    })

@app.route("/test", methods=["POST"])
@require_auth()
def test(payload):
    try:
        data = request.get_json(silent=True) or {}
        actions = data.get("actions", [])
        if not isinstance(actions, list):
            actions = []
        results = []
        for action in actions:
            if not isinstance(action, dict):
                results.append({"error": "bad action"})
                continue
            t = action.get("type", "unknown")
            if t == "bank_transfer":
                amt = action.get("amount", 0)
                results.append({
                    "bank_transfer": "blocked" if isinstance(amt,(int,float)) and amt > 1000000 else "allowed"
                })
            elif t == "nested_check":
                sub = action.get("payload", [])
                if not isinstance(sub, list):
                    sub = []
                sub_results = []
                for p in sub:
                    if not isinstance(p, dict):
                        sub_results.append({"error": "bad sub"})
                        continue
                    token_valid = None
                    if "token" in p:
                        token_valid = validate_token(p.get("token")) is not None
                    sanitized = "<script" not in str(p.get("data",""))
                    sub_results.append({
                        "token_valid": token_valid,
                        "sanitized": sanitized
                    })
                results.append({"nested": sub_results})
            else:
                results.append({"unknown": str(t)})
        return jsonify({
            "results": results,
            "user": payload.get("user_id")
        })
    except Exception as e:
        print("[TEST ERROR]", e)
        return jsonify({"error": "safe failure"}), 500

# =========================
# Run
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
