import httpx
from typing import List, Dict

# Security-Header, die wir prüfen wollen
SEC_HEADERS = [
    "x-content-type-options",
    "content-security-policy",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security"
]

def scan_target(url: str) -> List[Dict]:
    """
    Führt einen sicheren, Low-Impact Scan durch:
    - Prüft Erreichbarkeit (HTTP-Status)
    - Prüft das Vorhandensein wichtiger Security-Header
    """
    findings = []
    url = url.strip()
    if not url.startswith("http"):
        url = "https://" + url
    try:
        with httpx.Client(follow_redirects=True, timeout=10.0) as client:
            r = client.get(url)
            headers = {k.lower(): v for k, v in r.headers.items()}

            # Erreichbarkeit hinzufügen
            findings.append({
                "title": f"Reachability: {r.status_code}",
                "severity": "info",
                "details": f"URL={url}, server={headers.get('server','?')}"
            })

            # Fehlende Security-Header melden
            missing = [h for h in SEC_HEADERS if h not in headers]
            if missing:
                findings.append({
                    "title": "Missing security headers",
                    "severity": "medium",
                    "details": ", ".join(missing)
                })
    except Exception as e:
        findings.append({
            "title": "Scan error",
            "severity": "low",
            "details": str(e)
        })
    return findings
