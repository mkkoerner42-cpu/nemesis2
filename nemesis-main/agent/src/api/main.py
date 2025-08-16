from fastapi import FastAPI, Request, Form, Body
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv

from .config import settings
from .logging_conf import get_logger
from . import jobs
from . import storage

load_dotenv()
logger = get_logger()

app = FastAPI(title="Nemesis AIO (Bounty-enabled)", version="1.3.0")

# --- Pfade für Templates/Static ---
import pathlib
BASE_DIR = pathlib.Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# --- Models ---
class RuleIn(BaseModel):
    pattern: str

class WorkerBeat(BaseModel):
    name: str
    token: str

# --- Lifecycle ---
@app.on_event("startup")
def on_startup():
    # DB init
    storage.init_db()

    # Scheduler
    sched = BackgroundScheduler(timezone="UTC")
    # Core
    sched.add_job(jobs.job_cld_shadow, "interval",
                  minutes=settings.sched_cld_shadow_interval,
                  id="cld_shadow", replace_existing=True)
    sched.add_job(jobs.job_no_finding_loop, "interval",
                  minutes=settings.sched_no_finding_interval,
                  id="no_finding", replace_existing=True)
    sched.add_job(jobs.job_threat_feed, "interval",
                  minutes=settings.sched_threat_feed_interval,
                  id="threat_feed", replace_existing=True)
    # Optional/derived
    sched.add_job(jobs.job_prioritizer, "interval",
                  minutes=max(5, settings.sched_no_finding_interval // 2),
                  id="prioritizer", replace_existing=True)
    # Bounty & Scan automation
    sched.add_job(jobs.job_bounty_refresh, "interval",
                  minutes=settings.sched_bounty_refresh_interval,
                  id="bounty_refresh", replace_existing=True)
    sched.add_job(jobs.job_scan_queue, "interval",
                  minutes=settings.sched_scan_queue_interval,
                  id="scan_queue", replace_existing=True)
    # Workers maintenance
    sched.add_job(jobs.job_workers_maintenance, "interval",
                  minutes=settings.sched_worker_maintenance_interval,
                  id="workers_maintenance", replace_existing=True,
                  kwargs={"max_minutes_offline": settings.worker_offline_minutes})

    app.state.scheduler = sched
    sched.start()

    logger.info("Nemesis AIO gestartet.")
    if not settings.openai_api_key and settings.ai_provider == "openai":
        logger.warning("OPENAI_API_KEY fehlt – KI-Funktionen (OpenAI) sind deaktiviert.")

@app.on_event("shutdown")
def on_shutdown():
    sched = getattr(app.state, "scheduler", None)
    if sched:
        sched.shutdown(wait=False)

# --- Pages ---
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    f = storage.recent_findings(25)
    shadow, live = storage.list_rules(50)
    jl = storage.recent_jobs(50)
    plats = storage.list_platforms()
    targets = storage.list_targets(50)
    mods = storage.get_all_module_status()
    metrics = {
        "running_scans": storage.count_running_scans(),
        "running_workers": storage.count_workers_online(minutes=settings.worker_offline_minutes),
        "progress": storage.research_progress(),
    }
    safe_cfg = {
        "mode": settings.mode,
        "openai_api_key_set": bool(settings.openai_api_key),
    }
    return templates.TemplateResponse("index.html", {
        "request": request,
        "findings": f, "shadow": shadow, "live": live, "jobs": jl,
        "platforms": plats, "targets": targets, "mods": mods,
        "metrics": metrics, "cfg": safe_cfg
    })

@app.get("/modules", response_class=HTMLResponse)
def modules_page(request: Request):
    mods = storage.get_all_module_status()
    metrics = {
        "running_scans": storage.count_running_scans(),
        "running_workers": storage.count_workers_online(minutes=settings.worker_offline_minutes),
        "progress": storage.research_progress(),
    }
    return templates.TemplateResponse("modules.html", {"request": request, "mods": mods, "metrics": metrics})

@app.get("/workers", response_class=HTMLResponse)
def workers_page(request: Request):
    workers = storage.list_workers()
    metrics = {
        "running_scans": storage.count_running_scans(),
        "running_workers": storage.count_workers_online(minutes=settings.worker_offline_minutes),
        "progress": storage.research_progress(),
    }
    host = request.url.scheme + "://" + request.url.netloc
    return templates.TemplateResponse("workers.html", {"request": request, "workers": workers, "metrics": metrics, "host": host})

# --- Health / Config / Metrics ---
@app.get("/healthz")
def healthz():
    return {"ok": True, "message": "nemesis alive"}

@app.get("/config")
def show_config():
    safe = {
        "mode": settings.mode,
        "ai_provider": settings.ai_provider,
        "sched_cld_shadow_interval": settings.sched_cld_shadow_interval,
        "sched_no_finding_interval": settings.sched_no_finding_interval,
        "sched_threat_feed_interval": settings.sched_threat_feed_interval,
        "sched_bounty_refresh_interval": settings.sched_bounty_refresh_interval,
        "sched_scan_queue_interval": settings.sched_scan_queue_interval,
        "openai_api_key_set": bool(settings.openai_api_key),
    }
    return {"ok": True, "config": safe}

@app.get("/metrics")
def get_metrics():
    return {
        "ok": True,
        "metrics": {
            "running_scans": storage.count_running_scans(),
            "running_workers": storage.count_workers_online(minutes=settings.worker_offline_minutes),
            "progress": storage.research_progress(),
        }
    }

# --- Rules ---
@app.post("/rules/shadow")
def add_shadow_rule_json(rule: RuleIn = Body(...)):
    rid = storage.add_shadow_rule(rule.pattern)
    return {"ok": True, "id": rid}

@app.post("/rules/shadow/form")
def add_shadow_rule_form(pattern: str = Form(...)):
    storage.add_shadow_rule(pattern)
    return RedirectResponse(url="/", status_code=303)

@app.post("/cld/live/start")
def start_cld_live():
    jobs.job_cld_live()
    return {"ok": True, "message": "CLD live trigger"}

# --- Manual job triggers ---
@app.post("/fuzzing/start")
def start_fuzzing():
    jobs.job_fuzzing()
    return {"ok": True, "message": "fuzzing trigger"}

@app.post("/zero_day/hunt")
def zero_day_hunt(mode: Optional[str] = "cautious"):
    jobs.job_zero_day_hunt(mode=mode)
    return {"ok": True, "message": "zero-day hunt trigger", "mode": mode}

# --- Bounty / Targets ---
@app.post("/settings/platforms/add")
def add_platform_html(name: str = Form(...), base_url: str = Form(""), api_key: str = Form("")):
    storage.upsert_platform(name=name.strip(), base_url=base_url.strip() or None, api_key=api_key.strip() or None, enabled=True)
    return RedirectResponse(url="/", status_code=303)

@app.post("/settings/platforms/toggle")
def toggle_platform_html(pid: int = Form(...), enable: int = Form(...)):
    storage.set_platform_enabled(pid, enabled=bool(enable))
    return RedirectResponse(url="/", status_code=303)

@app.post("/bounties/refresh")
def bounty_refresh_html():
    jobs.job_bounty_refresh()
    return RedirectResponse(url="/", status_code=303)

@app.post("/scan/queue")
def scan_queue_html():
    jobs.job_scan_queue()
    return RedirectResponse(url="/", status_code=303)

# --- Workers ---
@app.post("/workers/register")
def register_worker_html(name: str = Form(...)):
    import secrets
    token = secrets.token_urlsafe(16)
    storage.register_worker(name=name.strip(), token=token)
    return RedirectResponse(url=f"/workers?created={name}&token={token}", status_code=303)

@app.post("/workers/heartbeat")
def workers_heartbeat(beat: WorkerBeat):
    ok = storage.heartbeat_worker(beat.name.strip(), beat.token.strip())
    return {"ok": ok}
