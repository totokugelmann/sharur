"""
Sharur SAIC - app/workers/celery_app.py

Configuracion de Celery para tareas asincronas de larga duracion
(ej: escaneos nmap completos, decompilacion de APKs si se agrega
ese modulo mas adelante).
"""

from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "sharur_saic",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.adquisicion", "app.workers.limpieza"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="America/Argentina/Buenos_Aires",
    enable_utc=True,
)
