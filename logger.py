from datetime import datetime

def log_attack(ip, endpoint, payload, attack_type):
    with open("attacks.log", "a") as f:
        f.write(
            f"{datetime.utcnow()} | {ip} | {endpoint} | {attack_type} | {payload}\n"
        )
