import os
from pydantic import BaseModel

class Settings(BaseModel):
    # --- AI Provider ---
    ai_provider: str = os.getenv("AI_PROVIDER", "openai").lower()  # "openai" | "ollama" | "none"
    openai_api_key: str | None = os.getenv("OPENAI_API_KEY")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    ollama_host: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

    # Runtime
    mode: str = os.getenv("NEMESIS_MODE", "cautious")
    port: int = int(os.getenv("NEMESIS_PORT", "8000"))

    # Scheduler-Intervalle (Minuten)
    sched_cld_shadow_interval: int = int(os.getenv("SCHED_CLD_SHADOW_INTERVAL", "10"))
    sched_no_finding_interval: int = int(os.getenv("SCHED_NO_FINDING_INTERVAL", "15"))
    sched_threat_feed_interval: int = int(os.getenv("SCHED_THREAT_FEED_INTERVAL", "30"))

    # Bounty/Scan
    sched_bounty_refresh_interval: int = int(os.getenv("SCHED_BOUNTY_REFRESH_INTERVAL", "20"))
    sched_scan_queue_interval: int = int(os.getenv("SCHED_SCAN_QUEUE_INTERVAL", "10"))

    # Workers
    worker_offline_minutes: int = int(os.getenv("WORKER_OFFLINE_MINUTES", "5"))
    sched_worker_maintenance_interval: int = int(os.getenv("SCHED_WORKER_MAINTENANCE_INTERVAL", "5"))

    # Logging
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

settings = Settings()
