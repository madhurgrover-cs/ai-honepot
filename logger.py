from datetime import datetime

def log_attack(attacker_id, ip, endpoint, attack_type, payload, llm_response):
    # Optional safety: never let attacker_id be empty
    if not attacker_id:
        attacker_id = "unknown"

    timestamp = datetime.utcnow().isoformat()

    log_line = (
        f"{timestamp} | "
        f"attacker_id={attacker_id} | "
        f"ip={ip} | "
        f"endpoint={endpoint} | "
        f"attack_type={attack_type} | "
        f"payload={payload} | "
        f"llm_response={llm_response}\n"
    )

    with open("attacks.log", "a", encoding="utf-8") as f:
        f.write(log_line)
