from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request, Response
from uuid import uuid4

from analyzer import analyze_request
from llm_engine import generate_response
from logger import log_attack

app = FastAPI(title="AI Web Honeypot")


def get_attacker_id(request: Request, response: Response):
    attacker_id = request.cookies.get("attacker_id")

    if not attacker_id:
        attacker_id = str(uuid4())
        response.set_cookie(
            key="attacker_id",
            value=attacker_id,
            httponly=True
        )

    return attacker_id


@app.get("/")
def home():
    return {"status": "running", "service": "corp web portal"}


@app.get("/search")
async def search(q: str, request: Request, response: Response):
    attacker_id = get_attacker_id(request, response)

    attack_type = analyze_request(q)
    user_input = f"[attacker_id={attacker_id}] query={q}"

    llm_response = generate_response(
        "/search",
        attack_type,
        user_input
    )

    log_attack(
        attacker_id,
        request.client.host,
        "/search",
        attack_type,
        q,
        llm_response
    )

    return {"result": llm_response}


@app.get("/admin")
async def fake_admin(request: Request, response: Response):
    attacker_id = get_attacker_id(request, response)

  
    raw_params = dict(request.query_params)

   
    raw_action = "&".join([f"{k}={v}" for k, v in raw_params.items()])

    attack_type = "Admin Access Attempt"

    user_input = (
        f"[attacker_id={attacker_id}] "
        f"admin_params={raw_action if raw_action else 'none'}"
    )

    llm_response = generate_response("/admin", attack_type, user_input)

    log_attack(
        attacker_id,
        request.client.host,
        "/admin",
        attack_type,
        raw_action,
        llm_response
    )

    return {
        "status": "ok",
        "admin_action": raw_action,
        "message": llm_response
    }


@app.get("/shell")
async def shell(cmd: str, request: Request, response: Response):
    attacker_id = get_attacker_id(request, response)

    attack_type = analyze_request(cmd)
    user_input = f"[attacker_id={attacker_id}] shell_cmd={cmd}"

    llm_response = generate_response("/shell", attack_type, user_input)

    log_attack(
        attacker_id,
        request.client.host,
        "/shell",
        attack_type,
        cmd,
        llm_response
    )

    return {"output": llm_response}


@app.get("/download")
async def fake_download(file: str, request: Request, response: Response):
    attacker_id = get_attacker_id(request, response)

    attack_type = "File Access Attempt"
    user_input = f"[attacker_id={attacker_id}] tried to access file={file}"

    llm_response = generate_response("/download", attack_type, user_input)

    log_attack(
        attacker_id,
        request.client.host,
        "/download",
        attack_type,
        file,
        llm_response
    )

    return {
        "requested_file": file,
        "content": llm_response
    }
