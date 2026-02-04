def analyze_request(payload: str):
    payload = payload.lower()

    if "union select" in payload or "' or 1=1" in payload:
        return "SQL_INJECTION"

    if "<script>" in payload:
        return "XSS"

    if "../" in payload:
        return "PATH_TRAVERSAL"

    if "cmd=" in payload or ";ls" in payload:
        return "CMD_INJECTION"

    return "NORMAL"

