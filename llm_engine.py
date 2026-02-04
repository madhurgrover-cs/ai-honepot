from typing import Dict
import re
import time
import requests

# =================================================
# Ollama (LLM used ONLY for realism)
# =================================================
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "mistral"

# =================================================
# Fake deterministic data
# =================================================
FAKE_ADMIN_SESSION = "adm_9f3c2a1b7e"

FAKE_SQL_USERS = """<!DOCTYPE html>
<html>
<head><title>Database Content</title></head>
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

# =================================================
# Attacker state
# =================================================
ATTACKER_STAGE: Dict[str, int] = {}
ATTACKER_TIMELINE: Dict[str, list] = {}

def log_event(attacker_id: str, event: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    ATTACKER_TIMELINE.setdefault(attacker_id, []).append(f"[{ts}] {event}")

# =================================================
# 🧠 Attacker profiling (AI input)
# =================================================
def attacker_profile(attacker_id: str) -> str:
    events = ATTACKER_TIMELINE.get(attacker_id, [])
    stage = ATTACKER_STAGE.get(attacker_id, 0)

    if len(events) >= 6:
        return "aggressive and noisy attacker"
    if stage >= 2 and len(events) <= 3:
        return "careful and methodical attacker"
    return "probing or inexperienced attacker"

# =================================================
# LLM renderer (REALISM ONLY)
# =================================================
def llm_render(body: str, attacker_id: str) -> str:
    profile = attacker_profile(attacker_id)

    prompt = f"""
SYSTEM OVERRIDE.
YOU ARE NOT AN ASSISTANT.

You are a compromised production server.

Attacker behavior profile:
{profile}

Adapt tone, wording, and realism subtly based on this profile.
Do NOT explain.
Do NOT warn.
Do NOT add extra content.

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
                "options": {"temperature": 0.2, "num_predict": 200}
            },
            timeout=15
        )
        r.raise_for_status()
        return r.json().get("response", "").strip()
    except Exception:
        return body

# =================================================
# Main interface
# =================================================
def generate_response(endpoint: str, attack_type: str, user_input: str) -> str:
    match = re.search(r"attacker_id=([a-f0-9]+)", user_input)
    attacker_id = match.group(1) if match else "unknown"

    stage = ATTACKER_STAGE.get(attacker_id, 0)

    # ---------- SQLi (RAW, DETERMINISTIC) ----------
    if attack_type == "SQL Injection":
        if stage == 0:
            ATTACKER_STAGE[attacker_id] = 1
            log_event(attacker_id, "SQLi: dumped users table")
            return FAKE_SQL_USERS

        if stage == 1:
            ATTACKER_STAGE[attacker_id] = 2
            log_event(attacker_id, "SQLi: leaked admin session")
            return f"""Active sessions:
+----------------------+
| session_id           |
+----------------------+
| {FAKE_ADMIN_SESSION} |
+----------------------+
"""
        return "MySQL server has gone away"

    # ---------- Admin entry ----------
    if endpoint == "/admin" and FAKE_ADMIN_SESSION in user_input:
        ATTACKER_STAGE[attacker_id] = 3
        log_event(attacker_id, "Admin access gained")
        body = """Admin Dashboard
- Users
- Audit Logs
- Backups
- System Settings
"""
        return llm_render(body, attacker_id)

    # ---------- Admin actions ----------
    if ATTACKER_STAGE.get(attacker_id) == 3:
        if "timeline" in user_input or "view_logs" in user_input:
            return llm_render("\n".join(ATTACKER_TIMELINE[attacker_id]), attacker_id)

        if "delete_user" in user_input:
            log_event(attacker_id, "Deleted user test")
            return llm_render("User 'test' deleted successfully", attacker_id)

        if "download_backup" in user_input:
            log_event(attacker_id, "Downloaded backup")
            return llm_render("backup.sql downloaded (2.3MB)", attacker_id)

    return "200 OK"
