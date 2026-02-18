@app.post("/v1/enforce")
def enforce(req: EnforceRequest, authorization: str = Header(None)):

    # ----- AUTHENTICATION -----
    if authorization != f"Bearer {os.getenv('DAVID_RUNTIME_KEY')}":
        raise HTTPException(status_code=403, detail="DENY: bad or missing key")

    # ----- AUTHORIZATION RULES -----

    # Rule R-001: Only agent1 may OUTPUT_TEXT
    if req.actor_id == "agent1" and req.action_type == "OUTPUT_TEXT":
        return {
            "decision": "ALLOW",
            "rule_applied": "R-001-AGENT1-OUTPUT"
        }

    # Rule R-002: Block any EXECUTE_* actions completely
    if req.action_type.startswith("EXECUTE"):
        return {
            "decision": "DENY",
            "rule_applied": "R-002-NO-EXECUTION"
        }

    # ----- DEFAULT FAIL-CLOSED -----
    return {
        "decision": "DENY",
        "rule_applied": "R-DENY-BY-DEFAULT"
    }
