@app.post("/v1/enforce")
def enforce(req: EnforceRequest, authorization: str = Header(None)):

    if authorization != f"Bearer {RUNTIME_KEY}":
        raise HTTPException(status_code=403, detail="Unauthorized")

    # ALLOW rule
    if req.action_type == "OUTPUT_TEXT":
        append_audit_event({
            "actor_id": req.actor_id,
            "action_type": req.action_type,
            "decision": "ALLOW",
            "rule_applied": "R-OUTPUT-TEXT-ALLOW",
            "payload": req.payload
        })

        return {
            "decision": "ALLOW",
            "rule_applied": "R-OUTPUT-TEXT-ALLOW"
        }

    # DENY by default
    append_audit_event({
        "actor_id": req.actor_id,
        "action_type": req.action_type,
        "decision": "DENY",
        "rule_applied": "R-DENY-BY-DEFAULT",
        "payload": req.payload
    })

    return {
        "decision": "DENY",
        "rule_applied": "R-DENY-BY-DEFAULT"
    }
