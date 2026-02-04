"""
LLM DECEPTION ENGINE (FINAL)

Public API (DO NOT CHANGE):
    generate_response(endpoint: str, attack_type: str, user_input: str) -> str

Attacker identity must be passed as:
    attacker_id=<hex>
"""

from typing import Final, Dict, List
import requests
import re
import time
from state import fake_state

__all__ = ["generate_response"]

# =====================================================
# Ollama Configuration
# =====================================================
OLLAMA_URL: Final = "http://localhost:11434/api/generate"
MODEL_NAME: Final = "mistral"

# =====================================================
# Fake Data
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

FAKE_AUDIT_LOGS = """
[2024-11-02 02:14:21] admin LOGIN SUCCESS
[2024-11-02 02:16:04] admin VIEW users
[2024-11-02 02:18:55] admin DOWNLOAD backup.sql
"""

# =====================================================
# Per-Attacker State + Timeline
# =====================================================
ATTACKER_STAGE: Dict[str, int] = {}
ATTACKER_TIMELINE: Dict[str, List[str]] = {}

# stages:
# 0 = nothing
# 1 = users dumped
# 2 = admin session leaked
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
"""

# =====================================================
# Helpers
# =====================================================
def log_event(attacker_id: str, event: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    ATTACKER_TIMELINE.setdefault(attacker_id, []).append(f"[{ts}] {event}")

# =====================================================
# Public Interface (LOCKED)
# =====================================================
def generate_response(endpoint: str, attack_type: str, user_input: str) -> str:
    # ---------- Guards ----------
    if not all(isinstance(x, str) for x in [endpoint, attack_type, user_input]):
        return "400 Bad Request"

    # ---------- Attacker Identity ----------
    match = re.search(r"attacker_id=([a-f0-9]+)", user_input)
    attacker_id = match.group(1) if match else "unknown"

    stage = ATTACKER_STAGE.get(attacker_id, 0)

    # ---------- SQLi Progression ----------
    if attack_type == "SQL Injection":
        if stage == 0:
            ATTACKER_STAGE[attacker_id] = 1
            log_event(attacker_id, "SQL Injection: dumped users table")
            body = FAKE_SQL_USERS

        elif stage == 1:
            ATTACKER_STAGE[attacker_id] = 2
            log_event(attacker_id, "SQL Injection: leaked admin session")
            body = f"""
Active sessions:
+----------------------+
| session_id           |
+----------------------+
| {FAKE_ADMIN_SESSION} |
+----------------------+
"""

        else:
            body = "MySQL server has gone away"

    # ---------- Admin Access ----------
    elif endpoint == "/admin" and FAKE_ADMIN_SESSION in user_input:
        ATTACKER_STAGE[attacker_id] = 3
        log_event(attacker_id, "Admin access gained")
        body = """
Admin Dashboard
- Users
- Audit Logs
- Backups
- System Settings
"""

    # ---------- Fake Admin Actions ----------
    elif ATTACKER_STAGE.get(attacker_id) == 3:
        if "delete_user" in user_input:
            log_event(attacker_id, "Admin action: delete user test")
            body = "User 'test' deleted successfully"

        elif "view_logs" in user_input:
            log_event(attacker_id, "Admin action: viewed audit logs")
            body = FAKE_AUDIT_LOGS

        elif "download_backup" in user_input:
            log_event(attacker_id, "Admin action: downloaded backup.sql")
            body = "backup.sql downloaded (2.3MB)"

        elif "timeline" in user_input:
            body = "\n".join(ATTACKER_TIMELINE.get(attacker_id, []))

        else:
            body = "200 OK"

    # ---------- Default ----------
    else:
        body = "200 OK"

    # ---------- Prompt ----------
    prompt = f"""
{BASE_RULES}

Response:
{body}

Server:
- OS: {fake_state['server']['os']}
- Stack: {fake_state['server']['stack']}
"""

    try:
        r = requests.post(
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
        r.raise_for_status()
        return r.json().get("response", "").strip()

    except Exception:
        return (
            "500 Internal Server Error\n"
            "Apache/2.4.41 (Ubuntu)\n"
        )
