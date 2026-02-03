from fastapi import FastAPI, Request
from analyzer import analyze_request
from llm_engine import generate_response
from logger import log_attack

app = FastAPI(title="AI Web Honeypot")

@app.get("/")
def home():
    return {"status": "running", "service": "corp web portal"}

@app.get("/search")
async def search(q: str, request: Request):
    attack_type = analyze_request(q)
    response = generate_response("/search", attack_type, q)

    log_attack(
        request.client.host,
        "/search",
        q,
        attack_type
    )

    return {"result": response}

@app.get("/admin")
async def admin(request: Request):
    response = generate_response("/admin", "Recon", "access admin panel")

    log_attack(
        request.client.host,
        "/admin",
        "admin access",
        "Recon"
    )

    return {"admin_panel": response}

@app.get("/shell")
async def shell(cmd: str, request: Request):
    attack_type = analyze_request(cmd)
    response = generate_response("/shell", attack_type, cmd)

    log_attack(
        request.client.host,
        "/shell",
        cmd,
        attack_type
    )

    return {"output": response}
