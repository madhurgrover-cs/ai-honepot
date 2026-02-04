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

@app.get("/search")
async def search(request: Request, q: str = ""):
    attacker_id = get_attacker_id(request)

    result = generate_response(
        endpoint="/search",
        payload=q,
        attacker_id=attacker_id
    )

    if result.lstrip().startswith("<!DOCTYPE html"):
        response = HTMLResponse(content=result)
    else:
        response = PlainTextResponse(content=result)

    response.set_cookie("attacker_id", attacker_id, httponly=True)
    return response

@app.get("/admin")
async def admin(request: Request):
    attacker_id = get_attacker_id(request)
    payload = str(request.query_params)

    result = generate_response(
        endpoint="/admin",
        payload=payload,
        attacker_id=attacker_id
    )

    response = PlainTextResponse(content=result)
    response.set_cookie("attacker_id", attacker_id, httponly=True)
    return response
