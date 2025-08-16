from loguru import logger
import sys
import os

def configure_logger():
    """
    Konfiguriert den globalen Logger:
    - Schreibt Logs in die Konsole (stdout)
    - Schreibt Logs in eine Datei (nemesis.log)
    - Log-Level wird aus ENV LOG_LEVEL gelesen (Default: INFO)
    """
    level = os.getenv("LOG_LEVEL", "INFO")
    logger.remove()  # Entfernt Standard-Handler
    logger.add(sys.stdout, level=level, enqueue=True, backtrace=False, diagnose=False)
    logger.add("nemesis.log", level=level, rotation="10 MB", retention="7 days", enqueue=True)
    return logger

get_logger = configure_logger
