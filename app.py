"""
Honeypot Web Application
FastAPI-based deception layer that mimics a vulnerable web application.
"""

from typing import Optional
from uuid import uuid4
from datetime import datetime
import secrets

from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from itsdangerous import URLSafeTimedSerializer, BadSignature

from llm_engine import generate_response
from analyzer import analyze_request
from logger import log_attack
from correlation_engine import track_attack_action, is_coordinated_attack
from threat_intel import analyze_threat, get_threat_level
from deception_engine import check_fake_security

# Advanced features
from ml_classifier import train_ml_classifier, predict_attack_type, detect_anomaly, track_credential_attempt
from external_threat_intel import lookup_threat_intel, add_threat, configure_threat_intel
from dashboard import get_dashboard_html, add_attack_to_dashboard, broadcast_attack, broadcast_stats, get_active_connections
from counter_intelligence import poison_tool_response, fingerprint_attacker, inject_fake_vulnerability, add_evasion_techniques
from fingerprinting import track_browser_fingerprint, find_related_attackers, get_fingerprinting_script
from alerts import send_attack_alert, send_brute_force_alert, send_coordinated_attack_alert, send_anomaly_alert, send_threat_ip_alert, configure_alerts, AlertSeverity
from demo_dashboard import get_demo_dashboard_html, update_demo_attack, update_demo_llm_thinking, update_demo_analysis, update_demo_threat_intel, update_demo_behavioral

# NEW: Hackathon Enhancement Modules
from attack_predictor import track_attack_for_prediction, get_attack_prediction, get_prediction_summary
from mitre_mapper import map_attack_to_mitre, get_attacker_ttps, get_mitre_matrix, match_to_apt_groups
from forensic_timeline import record_attack_event, record_canary_extraction, record_tool_detection, get_attack_timeline, generate_replay_script, generate_attack_narrative, get_timeline_html
from canary_analytics import register_canary_token, record_canary_usage, get_canary_journey, get_canary_effectiveness, get_attacker_canaries, get_canary_dashboard_data
from adaptive_deception import get_deception_strategy, adapt_response
from threat_sharing import generate_iocs, generate_stix_bundle, generate_threat_report
from playbook_generator import generate_incident_playbook, generate_sigma_rule
from export_engine import export_json, export_csv, export_attacks


# =========================
# SECURITY CONFIGURATION
# =========================
SECRET_KEY = secrets.token_urlsafe(32)  # Generate secure secret key
MAX_PAYLOAD_SIZE = 10000  # 10KB max payload
MAX_WEBSOCKET_CONNECTIONS = 100  # Global limit
MAX_WEBSOCKET_PER_IP = 5  # Per-IP limit

# Cookie serializer for signed cookies
cookie_serializer = URLSafeTimedSerializer(SECRET_KEY)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


# =========================
# APPLICATION SETUP
# =========================
app = FastAPI(
    title="Honeypot Application",
    description="AI-powered deception honeypot with security hardening",
    version="1.0.1"
)

# Add rate limit exception handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# =========================
# CONSTANTS
# =========================
ATTACKER_ID_COOKIE = "attacker_id"


# =========================
# HELPER FUNCTIONS
# =========================
def get_attacker_id(request: Request) -> str:
    """
    Retrieve or generate attacker tracking ID with signed cookie validation.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Unique attacker identifier (existing or newly generated)
    """
    signed_cookie = request.cookies.get(ATTACKER_ID_COOKIE)
    
    if signed_cookie:
        try:
            # Verify and decode signed cookie (24 hour expiry)
            attacker_id = cookie_serializer.loads(signed_cookie, max_age=86400)
            return attacker_id
        except (BadSignature, Exception):
            # Invalid or expired cookie, generate new ID
            pass
    
    # Generate new cryptographically secure ID
    attacker_id = secrets.token_urlsafe(16)
    return attacker_id


def set_attacker_cookie(response: Response, attacker_id: str) -> None:
    """
    Set signed attacker tracking cookie on response.
    
    Args:
        response: FastAPI response object
        attacker_id: Unique attacker identifier
    """
    # Sign the cookie value
    signed_value = cookie_serializer.dumps(attacker_id)
    
    response.set_cookie(
        key=ATTACKER_ID_COOKIE,
        value=signed_value,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
        max_age=86400  # 24 hours
    )


def create_response(content: str, attacker_id: str) -> Response:
    """
    Create appropriate response based on content type.
    
    Args:
        content: Response content from honeypot engine
        attacker_id: Unique attacker identifier
        
    Returns:
        HTMLResponse or PlainTextResponse with attacker cookie set
    """
    # Detect HTML content
    if content.lstrip().startswith("<!DOCTYPE html") or content.lstrip().startswith("<html"):
        response = HTMLResponse(content=content)
    else:
        response = PlainTextResponse(content=content)
    
    set_attacker_cookie(response, attacker_id)
    return response


def build_payload(request: Request, query_param: Optional[str] = None) -> str:
    """
    Build payload string from request data.
    
    Args:
        request: FastAPI request object
        query_param: Optional specific query parameter to extract
        
    Returns:
        Formatted payload string for analysis
    """
    if query_param is not None:
        return query_param
    
    # Use all query parameters if no specific param provided
    return str(request.query_params)


# =========================
# HONEYPOT ENDPOINTS
# =========================
@app.get("/search", response_class=Response)
@limiter.limit("20/minute")  # 20 requests per minute per IP
async def search_endpoint(request: Request, q: str = "") -> Response:
    """
    Vulnerable search endpoint - primary SQL injection target.
    
    Simulates a search feature that's vulnerable to SQL injection attacks.
    Tracks attacker progression through SQLi exploitation stages.
    
    Args:
        request: FastAPI request object
        q: Search query parameter (attack vector)
        
    Returns:
        Response with fake search results or leaked data
    """
    # Validate payload size
    if len(q) > MAX_PAYLOAD_SIZE:
        raise HTTPException(status_code=413, detail="Payload too large")
    
    attacker_id = get_attacker_id(request)
    payload = build_payload(request, query_param=q)
    
    # Get user agent
    user_agent = request.headers.get("user-agent")
    
    # Detect attack type
    attack_type = analyze_request(payload)
    
    # Check fake security measures (warnings but don't block)
    security_warnings = check_fake_security(attacker_id, payload)
    
    # Threat intelligence analysis
    threat_profile = analyze_threat(
        attacker_id=attacker_id,
        ip_address=request.client.host if request.client else None,
        user_agent=user_agent,
        attack_vector=attack_type,
        success=(attack_type != "NORMAL")
    )
    
    # Track attack for correlation
    campaign = track_attack_action(
        attacker_id=attacker_id,
        endpoint="/search",
        vector=attack_type,
        payload=payload,
        success=(attack_type == "SQL Injection"),
        data_leaked=("users" if attack_type == "SQL Injection" else None)
    )
    
    # NEW: Track for attack prediction
    track_attack_for_prediction(attacker_id, attack_type, "/search")
    
    # NEW: Map to MITRE ATT&CK
    mitre_mappings = map_attack_to_mitre(attack_type, payload, attacker_id)
    
    # NEW: Record in forensic timeline
    record_attack_event(
        attacker_id=attacker_id,
        attack_type=attack_type,
        endpoint="/search",
        payload=payload,
        success=(attack_type != "NORMAL")
    )
    
    # Generate honeypot response (now includes behavioral analysis)
    result = generate_response(
        endpoint="/search",
        payload=payload,
        attacker_id=attacker_id,
        user_agent=user_agent
    )
    
    # NEW: Apply adaptive deception
    # Get skill level from behavioral profile (if available)
    from behavioral_analyzer import get_behavioral_profile
    profile = get_behavioral_profile(attacker_id)
    skill_level = profile.skill_level if profile else "intermediate"
    result = adapt_response(result, attacker_id, skill_level)
    
    # Prepend security warnings if any
    if security_warnings:
        result = "\n".join(security_warnings) + "\n\n" + result
    
    # Log the attack with enhanced metadata
    log_attack(
        attacker_id=attacker_id,
        ip=request.client.host if request.client else "unknown",
        endpoint="/search",
        attack_type=attack_type,
        payload=payload,
        llm_response=result
    )
    
    # Broadcast to demo dashboard
    try:
        await broadcast_demo_update({
            "type": "attack",
            "attacker_id": attacker_id,
            "ip": request.client.host if request.client else "unknown",
            "endpoint": "/search",
            "attack_type": attack_type,
            "payload": payload,
            "timestamp": datetime.now().isoformat(),
            "threat_level": str(threat_profile.threat_level).split('.')[-1] if threat_profile else "MEDIUM",
            "skill_level": str(profile.skill_level).split('.')[-1] if profile else "UNKNOWN"
        })
    except Exception as e:
        print(f"[ERROR] Failed to broadcast to demo dashboard: {e}")
    
    return create_response(result, attacker_id)


@app.get("/admin", response_class=Response)
@limiter.limit("10/minute")  # 10 requests per minute per IP (stricter for admin)
async def admin_endpoint(request: Request) -> Response:
    """
    Fake admin panel endpoint.
    
    Simulates an admin interface that becomes accessible after
    successful exploitation. Tracks admin actions and data exfiltration.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Response with admin panel content or command results
    """
    attacker_id = get_attacker_id(request)
    payload = build_payload(request)
    
    # Get user agent
    user_agent = request.headers.get("user-agent")
    
    # Detect attack type
    attack_type = analyze_request(payload)
    
    # Threat intelligence analysis
    threat_profile = analyze_threat(
        attacker_id=attacker_id,
        ip_address=request.client.host if request.client else None,
        user_agent=user_agent,
        attack_vector=attack_type
    )
    
    # Track attack for correlation
    campaign = track_attack_action(
        attacker_id=attacker_id,
        endpoint="/admin",
        vector=attack_type,
        payload=payload,
        success=True  # Admin access is always "successful" in honeypot
    )
    
    # Check if coordinated attack
    is_coordinated = is_coordinated_attack(attacker_id)
    
    # Generate honeypot response
    result = generate_response(
        endpoint="/admin",
        payload=payload,
        attacker_id=attacker_id,
        user_agent=user_agent
    )
    
    # Add coordinated attack warning (for realism)
    if is_coordinated:
        result = "[Security Notice: Multiple attack vectors detected]\n\n" + result
    
    # Log the attack
    log_attack(
        attacker_id=attacker_id,
        ip=request.client.host if request.client else "unknown",
        endpoint="/admin",
        attack_type=attack_type,
        payload=payload,
        llm_response=result
    )
    
    return create_response(result, attacker_id)


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    """
    Landing page with links to vulnerable endpoints.
    
    Provides a realistic-looking entry point for attackers to discover
    and begin exploiting the honeypot.
    """
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Corporate Portal</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            h1 { color: #333; }
            .search-box { margin: 20px 0; }
            input[type="text"] { padding: 8px; width: 300px; }
            button { padding: 8px 16px; background: #007bff; color: white; border: none; cursor: pointer; }
            .links { margin-top: 30px; }
            .links a { display: block; margin: 10px 0; color: #007bff; text-decoration: none; }
        </style>
    </head>
    <body>
        <h1>Welcome to Corporate Portal</h1>
        <div class="search-box">
            <form action="/search" method="get">
                <input type="text" name="q" placeholder="Search...">
                <button type="submit">Search</button>
            </form>
        </div>
        <div class="links">
            <a href="/admin">Admin Panel</a>
            <a href="/search?q=test">Example Search</a>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.get("/health")
async def health_check() -> dict:
    """
    Health check endpoint for monitoring.
    
    Returns:
        Simple status object
    """
    return {"status": "ok"}


# =========================
# ERROR HANDLERS
# =========================
@app.exception_handler(404)
async def not_found_handler(request: Request, exc) -> PlainTextResponse:
    """
    Custom 404 handler to maintain honeypot illusion.
    
    Returns generic error without revealing it's a honeypot.
    """
    return PlainTextResponse(
        content="404 Not Found",
        status_code=404
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc) -> PlainTextResponse:
    """
    Custom 500 handler to maintain honeypot illusion.
    
    Returns generic error without revealing it's a honeypot.
    """
    return PlainTextResponse(
        content="500 Internal Server Error",
        status_code=500
    )


# =========================
# ADVANCED ENDPOINTS
# =========================
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Real-time attack monitoring dashboard."""
    return get_dashboard_html()


@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    """WebSocket for real-time dashboard updates."""
    import asyncio
    import json
    
    await websocket.accept()
    get_active_connections().append(websocket)
    
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            
            if message.get("type") == "get_stats":
                await broadcast_stats()
    except WebSocketDisconnect:
        if websocket in get_active_connections():
            get_active_connections().remove(websocket)


@app.post("/api/fingerprint")
async def fingerprint_api(request: Request):
    """Receive client-side fingerprint data."""
    try:
        client_data = await request.json()
        attacker_id = get_attacker_id(request)
        user_agent = request.headers.get("user-agent", "")
        
        # Track browser fingerprint with client data
        track_browser_fingerprint(
            attacker_id,
            user_agent,
            dict(request.headers),
            request.client.host if request.client else "unknown",
            client_data
        )
        
        return {"status": "ok"}
    except:
        return {"status": "error"}


@app.get("/demo", response_class=HTMLResponse)
async def demonstration_dashboard():
    """Live demonstration dashboard with detailed attack analysis."""
    return get_demo_dashboard_html()


# Global storage for demo WebSocket connections
_demo_connections = []


@app.websocket("/ws/demo")
async def websocket_demo(websocket: WebSocket):
    """WebSocket for demonstration dashboard real-time updates with connection limits."""
    import asyncio
    import json
    from datetime import datetime
    
    client_ip = websocket.client.host if websocket.client else "unknown"
    
    # Check global connection limit
    if len(_demo_connections) >= MAX_WEBSOCKET_CONNECTIONS:
        await websocket.close(code=1008, reason="Server at capacity")
        return
    
    # Check per-IP connection limit
    ip_connections = sum(1 for ws in _demo_connections 
                        if ws.client and ws.client.host == client_ip)
    if ip_connections >= MAX_WEBSOCKET_PER_IP:
        await websocket.close(code=1008, reason="Too many connections from your IP")
        return
    
    await websocket.accept()
    _demo_connections.append(websocket)
    
    try:
        while True:
            # Keep connection alive
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        if websocket in _demo_connections:
            _demo_connections.remove(websocket)


async def broadcast_demo_update(data: dict):
    """Broadcast update to all demo dashboard connections."""
    disconnected = []
    
    for connection in _demo_connections:
        try:
            await connection.send_json(data)
        except Exception as e:
            print(f"[WARNING] Failed to send to demo dashboard connection: {e}")
            disconnected.append(connection)
    
    # Remove disconnected clients
    for connection in disconnected:
        _demo_connections.remove(connection)


# =========================
# NEW: HACKATHON ENHANCEMENT ENDPOINTS
# =========================
@app.get("/api/prediction/{attacker_id}")
async def get_prediction(attacker_id: str):
    """Get attack prediction for attacker."""
    return get_prediction_summary(attacker_id)


@app.get("/api/mitre/{attacker_id}")
async def get_mitre(attacker_id: str):
    """Get MITRE ATT&CK mapping for attacker."""
    ttps = get_attacker_ttps(attacker_id)
    matrix = get_mitre_matrix(attacker_id)
    apt_matches = match_to_apt_groups(attacker_id)
    
    return {
        "ttps": ttps,
        "matrix": matrix,
        "apt_matches": [{"group": name, "similarity": f"{score:.1%}"} for name, score in apt_matches]
    }


@app.get("/api/timeline/{attacker_id}")
async def get_timeline(attacker_id: str):
    """Get forensic timeline for attacker."""
    timeline = get_attack_timeline(attacker_id)
    if not timeline:
        return {"error": "No timeline data"}
    
    return {
        "attacker_id": attacker_id,
        "duration": str(timeline.get_duration()),
        "total_attacks": timeline.total_attacks,
        "success_rate": f"{timeline.successful_attacks}/{timeline.total_attacks}",
        "attack_rate": f"{timeline.get_attack_rate():.2f}/min",
        "tools_used": timeline.tools_used,
        "endpoints_targeted": timeline.endpoints_targeted
    }


@app.get("/api/timeline/{attacker_id}/replay")
async def get_replay(attacker_id: str, speed: str = "5x"):
    """Get attack replay script."""
    from forensic_timeline import ReplaySpeed
    
    speed_map = {
        "realtime": ReplaySpeed.REALTIME,
        "2x": ReplaySpeed.FAST_2X,
        "5x": ReplaySpeed.FAST_5X,
        "10x": ReplaySpeed.FAST_10X,
        "instant": ReplaySpeed.INSTANT
    }
    
    replay_speed = speed_map.get(speed, ReplaySpeed.FAST_5X)
    return {"replay_script": generate_replay_script(attacker_id, replay_speed)}


@app.get("/api/timeline/{attacker_id}/narrative")
async def get_narrative(attacker_id: str):
    """Get attack narrative."""
    return {"narrative": generate_attack_narrative(attacker_id)}


@app.get("/api/canary/dashboard")
async def canary_dashboard():
    """Get canary analytics dashboard data."""
    return get_canary_dashboard_data()


@app.get("/api/canary/{attacker_id}")
async def get_canary_stats(attacker_id: str):
    """Get canary statistics for attacker."""
    return get_attacker_canaries(attacker_id)


@app.get("/api/canary/effectiveness")
async def canary_effectiveness():
    """Get canary effectiveness report."""
    return get_canary_effectiveness()


@app.get("/api/export/attacks")
async def export_attack_log():
    """Export attack log as CSV."""
    from logger import get_all_attacks
    attacks = get_all_attacks()
    csv_data = export_attacks(attacks)
    
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=attacks.csv"}
    )


@app.get("/api/threat-intel/{attacker_id}/iocs")
async def get_iocs(attacker_id: str):
    """Generate IOCs for attacker."""
    # Get attacker data
    from logger import get_attacker_history
    history = get_attacker_history(attacker_id)
    
    ips = list(set([h.get("ip", "") for h in history if h.get("ip")]))
    attack_types = list(set([h.get("attack_type", "") for h in history if h.get("attack_type")]))
    payloads = [h.get("payload", "") for h in history if h.get("payload")]
    
    return generate_iocs(attacker_id, ips, attack_types, payloads)


@app.get("/api/threat-intel/{attacker_id}/stix")
async def get_stix(attacker_id: str):
    """Generate STIX bundle for attacker."""
    from logger import get_attacker_history
    from behavioral_analyzer import get_behavioral_profile
    
    history = get_attacker_history(attacker_id)
    profile = get_behavioral_profile(attacker_id)
    
    attack_data = {
        "skill_level": profile.skill_level if profile else "unknown",
        "attack_types": list(set([h.get("attack_type", "") for h in history]))
    }
    
    return generate_stix_bundle(attacker_id, attack_data)


@app.get("/api/playbook/{attack_type}")
async def get_playbook(attack_type: str):
    """Generate incident response playbook."""
    attack_details = {
        "severity": "high" if "sql" in attack_type.lower() else "medium",
        "indicators": [f"Attack type: {attack_type}"]
    }
    
    playbook = generate_incident_playbook(attack_type, attack_details)
    
    return Response(
        content=playbook,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename={attack_type}_playbook.md"}
    )


# =========================
# STARTUP/SHUTDOWN HOOKS
# =========================
@app.on_event("startup")
async def startup_event():
    """Initialize honeypot on startup."""
    print("[*] Honeypot application starting...")
    print("[*] Waiting for attackers...")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    print("[*] Honeypot application shutting down...")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
