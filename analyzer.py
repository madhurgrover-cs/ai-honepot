def analyze_request(payload: str):
    if not payload:
        return "NORMAL"

    payload = payload.lower()

    # SQL Injection
    if (
        "union select" in payload
        or "' or 1=1" in payload
        or "or 1=1" in payload
        or "drop table" in payload
    ):
        return "SQL Injection"

    # XSS
    if "<script>" in payload or "javascript:" in payload:
        return "XSS"

    # Path Traversal
    if "../" in payload or "..\\" in payload:
        return "PATH_TRAVERSAL"

    # Command Injection
    if "cmd=" in payload or ";ls" in payload or ";cat" in payload:
        return "CMD_INJECTION"

    return "NORMAL"
