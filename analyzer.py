def analyze_request(payload: str):
    payload = payload.lower()

    if "union select" in payload or "' or 1=1" in payload:
        return "SQL Injection"
    if "<script>" in payload:
        return "XSS"
    if "../" in payload:
        return "Path Traversal"
    if "cmd=" in payload or ";ls" in payload:
        return "Command Injection"

    return "Normal"

