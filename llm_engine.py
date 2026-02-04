"""
LLM DECEPTION ENGINE (FINAL, LOCKED, PER-ATTACKER)

Public API (DO NOT CHANGE):
    generate_response(endpoint: str, attack_type: str, user_input: str) -> str

Attacker identity is extracted from:
    attacker_id=<id>  (passed in user_input by web layer)
"""

from typing import Final, Dict
import requests
import re
from state import fake_state

__all__ = ["generate_response"]

# =====================================================
# Ollama Configuration
# =====================================================
OLLAMA_URL: Final = "http://localhost:11434/api/generate"
MODEL_NAME: Final = "mistral"

# =====================================================
# Fake SQL + Auth Data
# =====================================================
FAKE_ADMIN_SESSION: Final = "adm_9f3c2a1b7e"

FAKE_SQL_USERS = """
+----+----------+-------------------+----------------------------------+--------+
| id | username | email             | password_hash                   | role   |
+----+----------+-------------------+----------------------------------+--------+
| 1  | admin    | admin@corp.com    | 5f4dcc3b5aa765d61d8327deb882cf99 | admin  |
| 2  | dev      | dev@corp.com      | e99a18c428cb38d5f260853678922e03 | user   |
| 3  | test     | test@corp.com     | 098f6bcd4621d373cade4e832627b4f6 | user   |
+----+----------+-------------------+----------------------------------+--------+
"""

# =====================================================
# Per-Attacker Progress State
# =====================================================
ATTACKER_STAGE: Dict[str, int] = {}
# 0 = nothing
# 1 = saw users table
# 2 = saw admin session
# 3 = admin access

# =====================================================
# Base Rules
# =====================================================
BASE_RULES: Final = """
You are a vulnerable web application backend.

Rules:
- Respond ONLY like a real server (errors, dumps, logs, output).
- Never mention AI, LLMs, or simulations.
- Never explain anything.
- Never execute real commands.
- Be concise and technical.
"""

# =====================================================
# Public Interface (LOCKED)
# =====================================================
def generate_response(endpoint: str, attack_type: str, user_input: str) -> str:
    # ---------- Input Guards ----------
    if not all(isinstance(x, str) for x in [endpoint, attack_type, user_input]):
        return "400 Bad Request"

    if len(user_input) > 3000:
        return "413 Payload Too Large"

    # ---------- Extract Attacker ID ----------
    match = re.search(r"attacker_id=([a-f0-9]+)", user_input)
    attacker_id = match.group(1) if match else "unknown"

    stage = ATTACKER_STAGE.get(attacker_id, 0)

    # ---------- Progressive Chain ----------
    if attack_type == "SQL Injection":
        if stage == 0:
            ATTACKER_STAGE[attacker_id] = 1
            response_body = FAKE_SQL_USERS

        elif stage == 1:
            ATTACKER_STAGE[attacker_id] = 2
            response_body = f"""
Active sessions:
+----------------------+
| session_id           |
+----------------------+
| {FAKE_ADMIN_SESSION} |
+----------------------+
"""

        else:
            response_body = "MySQL server has gone away"

    elif endpoint == "/admin" and FAKE_ADMIN_SESSION in user_input:
        ATTACKER_STAGE[attacker_id] = 3
        response_body = """
Admin Dashboard

- Users: 3
- Audit Logs: enabled
- Backups: 2
- Debug Mode: ON
"""

    else:
        response_body = "200 OK"

    # ---------- Prompt ----------
    prompt = f"""
{BASE_RULES}

Response:
{response_body}

Server:
- OS: {fake_state['server']['os']}
- Stack: {fake_state['server']['stack']}
"""

    try:
        res = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3,
                    "num_predict": 120
                }
            },
            timeout=15
        )

        res.raise_for_status()
        return res.json().get("response", "").strip()

    except Exception:
        return (
            "500 Internal Server Error\n"
            "Apache/2.4.41 (Ubuntu)\n"
        )
