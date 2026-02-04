from datetime import datetime

MAX_LEN = 300

def _clean(value):
    if value is None:
        return ""
    value = str(value).replace("\n", "\\n").replace("|", "/")
    return value[:MAX_LEN]

def log_attack(attacker_id, ip, endpoint, attack_type, payload, llm_response):
    if not attacker_id:
        attacker_id = "unknown"

    timestamp = datetime.utcnow().isoformat()

    log_line = (
        f"{timestamp} | "
        f"attacker_id={_clean(attacker_id)} | "
        f"ip={_clean(ip)} | "
        f"endpoint={_clean(endpoint)} | "
        f"attack_type={_clean(attack_type)} | "
        f"payload={_clean(payload)} | "
        f"llm_response={_clean(llm_response)}\n"
    )

    with open("attacks.log", "a", encoding="utf-8") as f:
        f.write(log_line)


