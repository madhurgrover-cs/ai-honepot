from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
import uuid

from llm_engine import generate_response

app = FastAPI()

def get_attacker_id(request: Request):
    attacker_id = request.cookies.get("attacker_id")
    if not attacker_id:
        attacker_id = uuid.uuid4().hex
    return attacker_id

# -------------------------------
# SEARCH (SQLi)
# -------------------------------
@app.get("/search")
async def search(request: Request, q: str = ""):
    attacker_id = get_attacker_id(request)
    user_input = f"{q}&attacker_id={attacker_id}"

    result = generate_response(
        endpoint="/search",
        attack_type="SQL Injection",
        user_input=user_input
    )

    if result.lstrip().startswith("<!DOCTYPE html"):
        response = HTMLResponse(content=result)
    else:
        response = PlainTextResponse(content=result)

    response.set_cookie("attacker_id", attacker_id, httponly=True)
    return response

# -------------------------------
# ADMIN
# -------------------------------
@app.get("/admin")
async def admin(request: Request):
    attacker_id = get_attacker_id(request)
    user_input = f"{request.query_params}&attacker_id={attacker_id}"

    result = generate_response(
        endpoint="/admin",
        attack_type="Recon",
        user_input=user_input
    )

    response = PlainTextResponse(content=result)
    response.set_cookie("attacker_id", attacker_id, httponly=True)
    return response
