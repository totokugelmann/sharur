"""
Sharur SAIC - app/core/config.py

Configuracion central de la aplicacion.

Todos los parametros sensibles o dependientes de entorno se cargan
desde variables de entorno (.env en desarrollo, secretos en
produccion). Nada de credenciales hardcodeadas.
"""

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # ── Identidad de la aplicacion ──────────────────────────────
    APP_NAME: str = "Sharur SAIC"
    APP_ENV: str = "development"  # development | staging | production
    APP_VERSION: str = "0.1.0"

    # ── Base de datos ────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+psycopg2://sharur:sharur@localhost:5432/sharur_saic"

    # ── Autenticacion / JWT ──────────────────────────────────────
    SECRET_KEY: str = "CHANGE_ME_IN_ENV"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # ── Roles habilitados a operar sobre casos ──────────────────
    # Solo dos roles de login existen en el sistema:
    # - admin: gestion de cuentas de operadores (alta/baja), sin
    #   participar del flujo de trabajo diario de un caso.
    # - operador: control funcional total del sistema (casos,
    #   ordenes, dispositivos, intervenciones, auditoria).
    #
    # Jueces, fiscales, defensores, etc. NO son roles de login:
    # su intervencion es el proceso judicial de siempre (orden
    # firmada en papel/expediente). El operador es quien CARGA
    # esos datos ya resueltos (numero de orden, juez firmante,
    # fundamentos) como texto dentro del sistema -- ver
    # schemas/orden.py, que pide esos campos como string, no como
    # cuenta de usuario.
    ROLE_ADMIN: str = "admin"
    ROLE_OPERADOR: str = "operador"

    # ── Redis / Celery (workers async) ──────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # ── LLM local (Ollama) para analisis evidence-first ─────────
    OLLAMA_URL: str = "http://localhost:11434/api/chat"
    OLLAMA_MODEL: str = "sharur-qwen"
    OLLAMA_TIMEOUT: int = 600

    # ── Fuente autoritativa de CVEs ──────────────────────────────
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY: str = ""  # opcional, mejora rate limit

    # ── Control de red / allow-list ──────────────────────────────
    # Interfaz de red o namespace usado para aplicar reglas de
    # allow-list por caso (ver services/network_control.py).
    NETWORK_CONTROL_BACKEND: str = "iptables"  # iptables | nftables | noop

    # ── Consola de comandos autorizados ──────────────────────────
    # Lista blanca de binarios que la consola manual puede invocar.
    # Deliberadamente NO incluye herramientas de explotacion.
    CONSOLE_ALLOWED_BINARIES: List[str] = [
        "nmap",
        "whois",
        "dig",
        "curl",
        "httpx",
        "katana",
        "nuclei",
        "testssl.sh",
        "graphw00f",
    ]

    # ── Almacenamiento de reportes / evidencia ───────────────────
    EVIDENCE_STORAGE_DIR: str = "./evidence_storage"
    REPORTS_DIR: str = "./reports"

    # ── Logging ───────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_DIR: str = "./logs"


@lru_cache
def get_settings() -> Settings:
    return Settings()
