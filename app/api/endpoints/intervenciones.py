"""
Sharur SAIC - app/api/endpoints/intervenciones.py

Endpoints de intervencion tecnica: analisis automatizado asistido
por IA y consola manual de comandos autorizados.

Todo lo que pasa por aca esta gateado a nivel de servicio (ver
gating_service.py). Un 403 aca puede significar tanto "tu rol de
API no alcanza" como "el gating rechazo la accion" -- el segundo
caso siempre viene acompañado del motivo_rechazo en el body.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role, settings
from app.models.dispositivo import Dispositivo
from app.schemas.auditoria import AnalisisIARequest, ConsolaComandoRequest, HallazgoRead
from app.services import analisis_ia_service, consola_service

router = APIRouter(prefix="/api/v1/intervenciones", tags=["intervenciones"])


@router.post("/analisis-ia", response_model=list[HallazgoRead])
def ejecutar_analisis_ia(
    payload: AnalisisIARequest,
    db: Session = Depends(get_db),
    user: dict = Depends(require_role(settings.ROLE_OPERADOR, settings.ROLE_ADMIN)),
):
    dispositivo = db.get(Dispositivo, payload.dispositivo_id)
    if dispositivo is None:
        raise HTTPException(404, "Dispositivo no encontrado.")

    try:
        hallazgos = analisis_ia_service.ejecutar_analisis_ia(
            db,
            caso_id=dispositivo.orden.caso_id,
            dispositivo_id=dispositivo.id,
            username=user["username"],
            herramienta=payload.herramienta,
            target=dispositivo.identificador,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    db.commit()
    for h in hallazgos:
        db.refresh(h)
    return hallazgos


@router.post("/consola")
def ejecutar_comando_consola(
    payload: ConsolaComandoRequest,
    db: Session = Depends(get_db),
    user: dict = Depends(require_role(settings.ROLE_OPERADOR, settings.ROLE_ADMIN)),
):
    dispositivo = db.get(Dispositivo, payload.dispositivo_id)
    if dispositivo is None:
        raise HTTPException(404, "Dispositivo no encontrado.")

    resultado = consola_service.ejecutar_comando_consola(
        db,
        caso_id=dispositivo.orden.caso_id,
        dispositivo_id=dispositivo.id,
        username=user["username"],
        binario=payload.binario,
        argumentos=payload.argumentos,
        notas=payload.notas or "",
    )
    db.commit()

    if not resultado.autorizado:
        raise HTTPException(
            403,
            detail={
                "motivo_rechazo": resultado.motivo_rechazo,
                "mensaje": "Accion rechazada por el motor de gating o la allow-list de binarios.",
            },
        )

    return {
        "status": resultado.status,
        "binario": resultado.binario,
        "argumentos": resultado.argumentos,
        "stdout": resultado.stdout,
        "stderr": resultado.stderr,
        "duracion_segundos": resultado.duracion_segundos,
        "evidencia_hash": resultado.evidencia_hash,
    }
