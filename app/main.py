"""
Sharur SAIC - app/main.py

Punto de entrada FastAPI.
"""

from fastapi import FastAPI

from app.api.endpoints import auditoria, auth, casos, dispositivos, intervenciones, ordenes
from app.core.config import get_settings
from app.core.logging import logger
import app.models  # noqa: F401  (registra todos los modelos para SQLAlchemy)

settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Framework de evidencia digital para la SAIC: gestion de casos, "
        "ordenes judiciales y alcance autorizado, gating de intervenciones, "
        "analisis evidence-first asistido por IA, cese, notificacion y "
        "auditoria con cadena de hashes verificable."
    ),
)

app.include_router(auth.router)
app.include_router(casos.router)
app.include_router(ordenes.router)
app.include_router(dispositivos.router)
app.include_router(intervenciones.router)
app.include_router(auditoria.router)


@app.on_event("startup")
async def on_startup() -> None:
    logger.info("%s v%s iniciado (entorno=%s)", settings.APP_NAME, settings.APP_VERSION, settings.APP_ENV)


@app.get("/health", tags=["sistema"])
def health() -> dict:
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION}
