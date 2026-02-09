"""
Honeypot Web Application
FastAPI-based deception layer that mimics a vulnerable web application.
"""

from typing import Optional
from uuid import uuid4

from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse

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


# =========================
# APPLICATION SETUP
# =========================
app = FastAPI(
    title="Honeypot Application",
    description="AI-powered deception honeypot",
    version="1.0.0"
)


# =========================
# CONSTANTS
# =========================
ATTACKER_ID_COOKIE = "attacker_id"


# =========================
# HELPER FUNCTIONS
# =========================
def get_attacker_id(request: Request) -> str:
    """
    Retrieve or generate attacker tracking ID.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Unique attacker identifier (existing or newly generated)
    """
    attacker_id = request.cookies.get(ATTACKER_ID_COOKIE)
    if not attacker_id:
        attacker_id = uuid4().hex
    return attacker_id


def set_attacker_cookie(response: Response, attacker_id: str) -> None:
    """
    Set attacker tracking cookie on response.
    
    Args:
        response: FastAPI response object
        attacker_id: Unique attacker identifier
    """
    response.set_cookie(
        key=ATTACKER_ID_COOKIE,
        value=attacker_id,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax"
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
    
    # Generate honeypot response (now includes behavioral analysis)
    result = generate_response(
        endpoint="/search",
        payload=payload,
        attacker_id=attacker_id,
        user_agent=user_agent
    )
    
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
    
    return create_response(result, attacker_id)


@app.get("/admin", response_class=Response)
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
_demo_connections: list[WebSocket] = []


@app.websocket("/ws/demo")
async def websocket_demo(websocket: WebSocket):
    """WebSocket for demonstration dashboard real-time updates."""
    import asyncio
    import json
    from datetime import datetime
    
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
    import json
    disconnected = []
    
    for connection in _demo_connections:
        try:
            await connection.send_json(data)
        except:
            disconnected.append(connection)
    
    # Remove disconnected clients
    for connection in disconnected:
        _demo_connections.remove(connection)


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
