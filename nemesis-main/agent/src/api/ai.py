from __future__ import annotations
from typing import List, Dict
from .config import settings
from .logging_conf import get_logger
import httpx

logger = get_logger()

# ---------- Helpers ----------
def _clean_lines(text: str) -> List[str]:
    lines = [l.strip() for l in (text or "").splitlines()]
    return [l for l in lines if l]

# ---------- OpenAI backend ----------
def _openai_chat(messages: List[Dict]) -> str:
    if not settings.openai_api_key:
        raise RuntimeError("OPENAI_API_KEY fehlt")
    try:
        from openai import OpenAI
        client = OpenAI(api_key=settings.openai_api_key)
        resp = client.chat.completions.create(
            model=settings.openai_model,
            messages=messages,
            temperature=0.2,
            max_tokens=400
        )
        return resp.choices[0].message.content or ""
    except Exception as e:
        logger.error(f"OpenAI-Error: {e}")
        raise

# ---------- Ollama backend ----------
def _ollama_generate(prompt: str) -> str:
    url = f"{settings.ollama_host.rstrip('/')}/api/generate"
    try:
        with httpx.Client(timeout=60) as client:
            r = client.post(url, json={"model": settings.ollama_model, "prompt": prompt, "stream": False})
            r.raise_for_status()
            data = r.json()
            return (data.get("response") or "").strip()
    except Exception as e:
        logger.error(f"Ollama-Error: {e}")
        raise

# ---------- Public API ----------
def generate_rule_candidates(context: str) -> List[str]:
    """
    Liefert kurze Pattern-Kandidaten (eine pro Zeile, max. ~10).
    """
    system = (
        "Du bist ein Sicherheitsassistent. Erzeuge prägnante, harmlose Pattern-Kandidaten "
        "zur späteren Überprüfung. Kein aktives Ausführen, nur Vorschläge. Eine pro Zeile."
    )
    user = f"Kontext:\n{context}\n\nLiefere 3-8 kurze Pattern-Kandidaten (je Zeile)."
    if settings.ai_provider == "openai":
        content = _openai_chat([
            {"role":"system","content":system},
            {"role":"user","content":user}
        ])
    elif settings.ai_provider == "ollama":
        content = _ollama_generate(system + "\n\n" + user)
    else:
        return ["header:missing_security_headers", "status:5xx_peek", "url:suspicious_subdomain"]

    return _clean_lines(content)

def summarize_findings(findings: List[Dict]) -> str:
    """
    Gibt eine kurze Zusammenfassung (1-3 Sätze) der Findings zurück.
    """
    if not findings:
        return "Keine Findings vorhanden."
    items = "\n".join(f"- {f.get('title','?')} [{f.get('severity','info')}]" for f in findings)
    system = "Du bist ein Sicherheitsassistent. Fasse prägnant und neutral zusammen (max. 3 Sätze)."
    user = f"Findings:\n{items}\n\nKurze Zusammenfassung:"
    if settings.ai_provider == "openai":
        return _openai_chat([
            {"role":"system","content":system},
            {"role":"user","content":user}
        ])
    elif settings.ai_provider == "ollama":
        return _ollama_generate(system + "\n\n" + user)
    else:
        return f"{len(findings)} Findings. Prüfe Details im Dashboard."
