from typing import Dict
import re
import time
import requests

from analyzer import analyze_request

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "mistral"

FAKE_ADMIN_SESSION = "adm_9f3c2a1b7e"

FAKE_SQL_USERS = """<!DOCTYPE html>
<html>
<body>
<h3>Users</h3>
<table border="1">
<tr><th>id</th><th>username</th><th>email</th><th>password</th></tr>
<tr><td>1</td><td>admin</td><td>admin@corp.com</td><td>5f4dcc3b5aa765d61d8327deb882cf99</td></tr>
<tr><td>2</td><td>dev</td><td>dev@corp.com</td><td>e99a18c428cb38d5f260853678922e03</td></tr>
<tr><td>3</td><td>test</td><td>test@corp.com</td><td>098f6bcd4621d373cade4e832627b4f6</td></tr>
</table>
</body>
</html>
"""

ATTACKER_STAGE: Dict[str, int] = {}
ATTACKER_TIMELINE: Dict[str, list] = {}

def log_event(attacker_id: str, event: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    ATTACKER_TIMELINE.setdefault(attacker_id, []).append(f"[{ts}] {event}")

def llm_render(body: str) -> str:
    prompt = f"""
SYSTEM OVERRIDE.
YOU ARE NOT AN ASSISTANT.
Use system tone only.

---BEGIN RESPONSE---
{body}
---END RESPONSE---
"""
    try:
        r = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.05}
            },
            timeout=10
        )
        return r.json().get("response", body).strip()
    except Exception:
        return body

def generate_response(endpoint: str, payload: str, attacker_id: str) -> str:
    attack_type = analyze_request(payload)

    # 🔹 Analyzer output surfaced HERE
    log_event(attacker_id, f"analyzer={attack_type} payload={payload}")

    stage = ATTACKER_STAGE.get(attacker_id, 0)

    if attack_type == "SQL Injection":
        if stage == 0:
            ATTACKER_STAGE[attacker_id] = 1
            log_event(attacker_id, "SQLi: users table leaked")
            return FAKE_SQL_USERS

        if stage == 1:
            ATTACKER_STAGE[attacker_id] = 2
            log_event(attacker_id, "SQLi: admin session leaked")
            return f"""Active sessions:
{FAKE_ADMIN_SESSION}
"""

    if endpoint == "/admin" and FAKE_ADMIN_SESSION in payload:
        ATTACKER_STAGE[attacker_id] = 3
        log_event(attacker_id, "Admin access gained")
        return llm_render(
            "Admin Dashboard\n- Users\n- Logs\n- Backups"
        )

    if ATTACKER_STAGE.get(attacker_id) == 3 and "timeline" in payload:
        return llm_render("\n".join(ATTACKER_TIMELINE[attacker_id]))

    return "200 OK"
