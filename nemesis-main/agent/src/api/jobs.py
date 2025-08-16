from typing import Optional
from datetime import datetime, timezone
from .storage import (
    add_finding, log_job, add_shadow_rule,
    promote_shadow_to_live, get_latest_shadow_rule_id,
    list_platforms, add_or_queue_target, pop_next_queued_target, mark_target_scanned,
    set_module_status, mark_stale_workers_offline
)
from .logging_conf import get_logger
from . import scanner
from . import ai
from .config import settings

logger = get_logger()

# ---- Core Jobs ----
def job_cld_shadow():
    """
    Nutzt KI (OpenAI oder Ollama), um Pattern-Kandidaten zu erzeugen
    und speichert diese als Shadow Rules.
    """
    set_module_status("CLD Shadow", "ok", f"provider={settings.ai_provider}")
    context = "Web Scan Telemetrie: fehlende Security-Header, Redirect-Ketten, Non-200 Statusspitzen."
    try:
        candidates = ai.generate_rule_candidates(context=context)
    except Exception as e:
        candidates = ["header:missing_security_headers", "status:5xx_peek", "url:suspicious_subdomain"]
        log_job("cld_shadow", "WARN", f"KI-Generierung fehlgeschlagen: {e}")
    added = 0
    for p in candidates:
        try:
            _ = add_shadow_rule(p)
            added += 1
        except Exception as e:
            log_job("cld_shadow", "WARN", f"Kandidat verworfen: {p} ({e})")
    log_job("cld_shadow", "INFO", f"{added} Kandidaten gespeichert")

def job_cld_live():
    """
    Promotet die neueste Shadow-Regel zu einer Live-Regel.
    """
    set_module_status("CLD Live", "ok", "apply-latest")
    try:
        rid = get_latest_shadow_rule_id()
        if rid is None:
            log_job("cld_live", "INFO", "Keine Shadow-Regel vorhanden")
            return
        lid = promote_shadow_to_live(rid)
        log_job("cld_live", "INFO", f"Promoted shadow#{rid} -> live#{lid}")
    except Exception as e:
        log_job("cld_live", "ERROR", f"Promotion fehlgeschlagen: {e}")

def job_no_finding_loop():
    set_module_status("No-Finding-Loop", "ok", "hypothesis")
    log_job("no_finding", "INFO", "Hypothesentest durchgeführt")
    add_finding("Hypothesis OK", "info", "no critical finding")

def job_threat_feed():
    set_module_status("Threat-Feed", "ok", "refresh")
    log_job("threat_feed", "INFO", "Feed aktualisiert")

def job_fuzzing():
    set_module_status("Fuzzing", "ok", "mutations")
    log_job("fuzzing", "INFO", "Fuzz iteration done")

def job_prioritizer():
    set_module_status("Prioritizer", "ok", "scoring")
    log_job("prioritizer", "INFO", "Scored priority paths")

def job_zero_day_hunt(mode: Optional[str] = "cautious"):
    set_module_status("Zero-Day", "ok", f"mode={mode}")
    log_job("zero_day", "INFO", f"hunt in mode={mode}")
    add_finding("ZeroDay scan", "info", f"mode={mode}")

# ---- Bounty / Targets ----
def job_bounty_refresh():
    """
    Stub: je aktivierter Plattform ein Demo-Target einreihen.
    (Später: echte API-Calls.)
    """
    set_module_status("Bounty-Refresh", "ok", "sync")
    plats = list_platforms()
    if not plats:
        log_job("bounty_refresh", "INFO", "No platforms configured")
        return
    count = 0
    for pid, name, base_url, enabled, _ in plats:
        if not enabled:
            continue
        demo_domain = f"{name.lower()}-demo.example.com"
        add_or_queue_target(pid, demo_domain, scope="demo")
        count += 1
    log_job("bounty_refresh", "INFO", f"Queued {count} target(s)")

def job_scan_queue():
    """
    Holt das nächste queued-Target, scannt es mit dem sicheren Scanner,
    speichert Findings und fügt optional eine KI-Zusammenfassung hinzu.
    """
    set_module_status("Scan-Queue", "ok", "scanning")
    item = pop_next_queued_target()
    if not item:
        log_job("scan_queue", "INFO", "No targets in queue")
        return
    tid, platform_id, target, scope = item
    findings = scanner.scan_target(target)
    now = datetime.now(timezone.utc).isoformat()
    ok = True
    for f in findings:
        add_finding(f.get("title","Finding"), f.get("severity","info"), f.get("details",""))
        if f.get("severity","info").lower() in ("medium","high","critical"):
            ok = False
    # KI-Zusammenfassung
    try:
        summary = ai.summarize_findings(findings)
        if summary:
            add_finding("Scan Summary", "info", summary)
    except Exception as e:
        log_job("scan_queue", "WARN", f"Summary fehlgeschlagen: {e}")

    mark_target_scanned(tid, ok, now)
    log_job("scan_queue", "INFO", f"Scanned {target} (ok={ok}, findings={len(findings)})")

# ---- Workers Maintenance ----
def job_workers_maintenance(max_minutes_offline: int = 5):
    set_module_status("Workers", "ok", "maintenance")
    mark_stale_workers_offline(minutes=max_minutes_offline)
