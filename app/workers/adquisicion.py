"""
Sharur SAIC - app/workers/adquisicion.py

Tareas asincronas de adquisicion de EVIDENCIA DE RECONOCIMIENTO
(no de acceso remoto a dispositivos). Se usa para escaneos largos
(ej: nmap perfil "completo" sobre 65535 puertos) que no conviene
correr sincronicamente dentro de un request HTTP.

Alcance identico al de tools_service.py: mismas herramientas
permitidas, mismo paso obligado por gating_service antes de
ejecutar. Este worker es solo la variante asincrona de esas
mismas llamadas.

Nota de nombre: el archivo se llama "adquisicion.py" siguiendo la
convencion de carpeta original del proyecto (adquisicion de
evidencia), no "acceso remoto". No implementa, ni debe
implementar, ningun mecanismo de intrusion o post-explotacion.
"""

from app.models.base import SessionLocal
from app.services import tools_service
from app.workers.celery_app import celery_app


@celery_app.task(name="adquisicion.nmap_completo")
def tarea_nmap_completo(caso_id: int, dispositivo_id: int, username: str, target: str) -> dict:
    db = SessionLocal()
    try:
        resultado = tools_service.run_nmap(
            db, caso_id=caso_id, dispositivo_id=dispositivo_id, username=username, target=target, profile="completo"
        )
        db.commit()
        return {
            "status": resultado.status,
            "duration_seconds": resultado.duration_seconds,
            "evidence_hash": resultado.evidence_hash,
        }
    finally:
        db.close()
