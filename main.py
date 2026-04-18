+= 0.7
            reasons.add("Path traversal attempt")
        
        # Command injection detection
        if re.search(self.command_injection, text, re.IGNORECASE):
            risk += 0.8
            reasons.add("Command injection attempt")
        
        # XSS detection
        if re.search(self.xss_patterns, text, re.IGNORECASE):
            risk += 0.5
            reasons.add("Potential XSS payload")
        
        # Excessive nesting check
        def get_depth(d, level=1):
            if not isinstance(d, dict) or not d or level > 10:
                return level
            return max(get_depth(v, level + 1) for v in d.values())
        
        try:
            if get_depth(payload) > 5:
                risk += 0.4
                reasons.add("Excessive nesting")
        except (RecursionError, Exception):
            risk += 0.5
            reasons.add("Malformed nested structure")
        
        # Null bytes detection
        if '\x00' in text:
            risk += 0.9
            reasons.add("Null byte injection attempt")
        
        risk = min(1.0, risk)
        
        # Fail-closed posture
        decision = "block" if risk >= settings.risk_threshold else "allow"
        
        return decision, risk, reasons

risk_analyzer = RiskAnalyzer()

# =========================
# MIDDLEWARE
# =========================
@app.middleware("http")
async def add_request_context(request: Request, call_next):
    """Add request ID and logging context"""
    request_id = str(uuid.uuid4())
    request_id_var.set(request_id)
    
    start_time = time.time()
    
    logger.info(f"Request started: {request.method} {request.url.path} - ID: {request_id}")
    
    try:
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        
        duration = time.time() - start_time
        logger.info(f"Request completed: {request_id} - Status: {response.status_code} - Duration: {duration:.3f}s")
        
        return response
    except Exception as e:
        logger.error(f"Request failed: {request_id} - Error: {str(e)}")
        raise

# =========================
# BACKGROUND TASKS
# =========================
async def cleanup_task():
    """Periodic cleanup of stale data"""
    while True:
        try:
            await asyncio.sleep(300)  # Every 5 minutes
            now = time.time()
            
            # Clean rate tracker
            async with rate_lock:
                for ip in list(rate_tracker.keys()):
                    rate_tracker[ip] = [t for t in rate_tracker[ip] if now - t < 60]
                    if not rate_tracker[ip]:
                        del rate_tracker[ip]
            
            # Clean blocked IPs
            async with block_lock:
                for ip in list(blocked_ips.keys()):
                    if now >= blocked_ips[ip]:
                        del blocked_ips[ip]
            
            # Clean nonces
            async with nonce_lock:
                expired = [n for n, t in nonce_store.items() if now - t > settings.nonce_ttl]
                for n in expired:
                    del nonce_store[n]
            
            logger.debug(f"Cleanup completed - Active IPs: {len(rate_tracker)}, Blocked: {len(blocked_ips)}, Nonces: {len(nonce_store)}")
            
        except Exception as e:
            logger.error(f"Cleanup task error: {e}")

# =========================
# STARTUP/SHUTDOWN
# =========================
@app.on_event("startup")
async def startup():
    global last_hash_state
    
    logger.info(f"Starting David AI Core v4.1 in {settings.environment} mode")
    
    # Validate configuration
    if settings.environment == "production":
        if settings.jwt_secret == "CHANGE_THIS_NOW":
            raise RuntimeError("JWT_SECRET must be changed in production!")
        logger.info("Production configuration validated")
    
    # Initialize database
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                timestamp REAL,
                ip TEXT,
                decision TEXT,
                risk REAL,
                reasons TEXT,
                prev_hash TEXT,
                hash TEXT,
                request_id TEXT
            )
        """)
        
        # Add request_id column if not exists (migration)
        try:
            await db.execute("ALTER TABLE audit_log ADD COLUMN request_id TEXT")
        except:
            pass  # Column already exists
        
        # Get last hash
        async with db.execute("SELECT hash FROM audit_log ORDER BY timestamp DESC LIMIT 1") as cursor:
            row = await cursor.fetchone()
            if row:
                last_hash_state = row[0]
                logger.info(f"Loaded audit chain head: {last_hash_state[:16]}...")
        
        await db.commit()
    
    # Start background tasks
    asyncio.create_task(cleanup_task())
    
    logger.info("David AI Core started successfully")

@app.on_event("shutdown")
async def shutdown():
    logger.info("David AI Core shutting down")

# =========================
# AUTHENTICATION
# =========================
async def verify_auth(authorization: Optional[str] = Header(None), x_nonce: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    
    try:
        token = authorization.replace("Bearer ", "")
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "iat"]}
        )
        
        # Log successful auth
        logger.debug(f"JWT validated for subject: {payload.get('sub', 'unknown')}")
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    if not x_nonce:
        raise HTTPException(status_code=400, detail="Missing X-Nonce header")
    
    now = time.time()
    
    # Check nonce with lock
    async with nonce_lock:
        # Clean expired nonces
        expired = [n for n, t in nonce_store.items() if now - t > settings.nonce_ttl]
        for n in expired:
            del nonce_store[n]
        
        if x_nonce in nonce_store:
            logger.warning(f"Replay attack detected with nonce: {x_nonce}")
            raise HTTPException(status_code=400, detail="Replay attack detected")
        
        nonce_store[x_nonce] = now

# =========================
# RATE LIMITING
# =========================
async def check_rate_limit(request: Request):
    ip = request.client.host
    now = time.time()
    
    # Check if blocked
    async with block_lock:
        if ip in blocked_ips and now < blocked_ips[ip]:
            remaining_block = int(blocked_ips[ip] - now)
            raise HTTPException(
                status_code=403, 
                detail=f"IP blocked for {remaining_block} more seconds"
            )
    
    # Update rate tracker
    async with rate_lock:
        window = [t for t in rate_tracker[ip] if now - t < 60]
        window.append(now)
        rate_tracker[ip] = window
        
        if len(window) > settings.rate_limit:
            async with block_lock:
                blocked_ips[ip] = now + settings.block_time
            logger.warning(f"IP {ip} rate limited and blocked for {settings.block_time}s")
            raise HTTPException(
                status_code=429, 
                detail=f"Rate limit exceeded. Blocked for {settings.block_time} seconds"
            )

# =========================
# AUDIT CHAIN
# =========================
async def log_to_audit(ip: str, decision: str, risk: float, reasons: Set[str]) -> str:
    global last_hash_state
    
    block_id = str(uuid.uuid4())
    ts = time.time()
    request_id = request_id_var.get()
    reasons_str = ", ".join(sorted(reasons)) if reasons else "None"
    data_str = f"{ip}|{decision}|{risk}|{reasons_str}|{request_id}"
    
    async with hash_lock:
        new_hash = hashlib.sha256(
            f"{last_hash_state}|{data_str}".encode()
        ).hexdigest()
        
        async with aiosqlite.connect(settings.db_path) as db:
            await db.execute(
                "INSERT INTO audit_log VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (block_id, ts, ip, decision, risk, reasons_str, last_hash_state, new_hash, request_id)
            )
            await db.commit()
        
        old_hash = last_hash_state[:16]
        last_hash_state = new_hash
        
        logger.info(f"Audit log created: {block_id} - Decision: {decision} - Risk: {risk:.2f} - Chain: {old_hash}... -> {new_hash[:16]}...")
        
        return new_hash

async def get_audit_count() -> int:
    async with aiosqlite.connect(settings.db_path) as db:
        async with db.execute("SELECT COUNT(*) FROM audit_log") as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

# =========================
# ENDPOINTS
# =========================
@app.post("/analyze", dependencies=[Depends(verify_auth), Depends(check_rate_limit)])
async def analyze(request: Request, data: Payload):
    """
    Analyze payload for security risks with fail-closed enforcement
    """
    start_time = time.time()
    request_id = request_id_var.get()
    
    logger.info(f"Analyzing payload - Request ID: {request_id} - IP: {request.client.host}")
    
    # Analyze risk
    decision, risk, reasons = risk_analyzer.analyze(data.payload)
    
    # Log to audit chain
    audit_hash = await log_to_audit(request.client.host, decision, risk, reasons)
    
    latency_ms = round((time.time() - start_time) * 1000, 2)
    
    # Fail-closed enforcement
    if decision != "allow":
        logger.warning(f"Request blocked - ID: {request_id} - Risk: {risk:.2f} - Reasons: {reasons}")
        
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Denied by David AI Security Gateway",
                "decision": decision,
                "risk_score": risk,
                "reasons": list(reasons),
                "audit_hash": audit_hash,
                "request_id": request_id,
                "latency_ms": latency_ms
            }
        )
    
    logger.info(f"Request approved - ID: {request_id} - Risk: {risk:.2f}")
    
    return {
        "status": "approved",
        "decision": decision,
        "risk_score": risk,
        "reasons": list(reasons),
        "audit_hash": audit_hash,
        "request_id": request_id,
        "latency_ms": latency_ms
    }

@app.get("/", response_model=HealthResponse)
async def health():
    """Health check endpoint"""
    try:
        # Test database connection
        async with aiosqlite.connect(settings.db_path) as db:
            await db.execute("SELECT 1")
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"
        logger.error(f"Database health check failed: {e}")
    
    return {
        "service": "David AI Core",
        "version": "4.1.0",
        "status": "healthy" if db_status == "connected" else "degraded",
        "environment": settings.environment,
        "database": db_status,
        "chain_head": last_hash_state[:16],
        "active_ips": len(rate_tracker),
        "blocked_ips": len(blocked_ips),
        "active_nonces": len(nonce_store)
    }

@app.get("/metrics", response_model=MetricsResponse)
async def get_metrics():
    """Prometheus-compatible metrics endpoint"""
    audit_count = await get_audit_count()
    
    return {
        "rate_limited_ips": len(rate_tracker),
        "blocked_ips_count": len(blocked_ips),
        "active_nonces": len(nonce_store),
        "audit_chain_length": audit_count,
        "uptime_seconds": time.time() - start_time if 'start_time' in globals() else 0
    }

@app.get("/audit/verify")
async def verify_chain():
    """Verify the integrity of the audit chain"""
    async with aiosqlite.connect(settings.db_path) as db:
        async with db.execute("SELECT * FROM audit_log ORDER BY timestamp ASC") as cursor:
            rows = await cursor.fetchall()
    
    if not rows:
        return {"status": "EMPTY", "records": 0}
    
    prev = "GENESIS_DAVID"
    verified_count = 0
    
    for row in rows:
        block_id, ts, ip, decision, risk, reasons, prev_hash, current_hash, request_id = row
        
        data_str = f"{ip}|{decision}|{risk}|{reasons}|{request_id or ''}"
        recalculated = hashlib.sha256(f"{prev}|{data_str}".encode()).hexdigest()
        
        if prev_hash != prev or current_hash != recalculated:
            logger.error(f"Chain verification failed at block {block_id}")
            return {
                "status": "FAILED",
                "bad_record": block_id,
                "expected_hash": recalculated,
                "actual_hash": current_hash,
                "verified_records": verified_count
            }
        
        prev = current_hash
        verified_count += 1
    
    logger.info(f"Audit chain verified: {verified_count} records")
    
    return {
        "status": "VERIFIED",
        "records": verified_count,
        "chain_head": prev[:16]
    }

@app.get("/audit/recent")
async def get_recent_audit_logs(limit: int = 100):
    """Get recent audit log entries"""
    async with aiosqlite.connect(settings.db_path) as db:
        async with db.execute(
            "SELECT id, timestamp, ip, decision, risk, reasons, prev_hash, hash, request_id "
            "FROM audit_log ORDER BY timestamp DESC LIMIT ?", 
            (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
    
    return {
        "count": len(rows),
        "entries": [
            {
                "id": row[0],
                "timestamp": row[1],
                "ip": row[2],
                "decision": row[3],
                "risk": row[4],
                "reasons": row[5],
                "prev_hash": row[6][:16] + "..." if row[6] else None,
                "hash": row[7][:16] + "...",
                "request_id": row[8]
            }
            for row in rows
        ]
    }

@app.get("/audit/stats")
async def get_audit_stats():
    """Get audit statistics"""
    async with aiosqlite.connect(settings.db_path) as db:
        # Total counts
        async with db.execute("SELECT COUNT(*), decision FROM audit_log GROUP BY decision") as cursor:
            decision_counts = {row[1]: row[0] for row in await cursor.fetchall()}
        
        # Average risk by decision
        async with db.execute("SELECT decision, AVG(risk) FROM audit_log GROUP BY decision") as cursor:
            avg_risk = {row[0]: round(row[1], 3) for row in await cursor.fetchall()}
        
        # Top reasons
        async with db.execute(
            "SELECT reasons, COUNT(*) as count FROM audit_log "
            "WHERE reasons != 'None' GROUP BY reasons ORDER BY count DESC LIMIT 10"
        ) as cursor:
            top_reasons = [{"reason": row[0], "count": row[1]} for row in await cursor.fetchall()]
    
    return {
        "total_records": sum(decision_counts.values()),
        "decision_breakdown": decision_counts,
        "average_risk_by_decision": avg_risk,
        "top_blocking_reasons": top_reasons,
        "current_chain_head": last_hash_state[:16]
    }

# Set start time for uptime tracking
start_time = time.time()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.environment == "development",
        log_level=settings.log_level.lower()
    )
```
