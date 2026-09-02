"""
Sharur SAIC - app/api/endpoints/dispositivos.py

Endpoints de dispositivos: alta, hallazgo casual, cese.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, require_role, settings
from app.models.dispositivo import Dispositivo
from app.models.orden import Orden
from app.schemas.dispositivo import (
    DispositivoCeseRequest,
    DispositivoCreate,
    DispositivoHallazgoCasualCreate,
    DispositivoRead,
)
from app.services import cese_service, orden_service

router = APIRouter(prefix="/api/v1/dispositivos", tags=["dispositivos"])


@router.post("", response_model=DispositivoRead, status_code=201)
def agregar_dispositivo(
    payload: DispositivoCreate,
    db: Session = Depends(get_db),
    user: dict = Depends(require_role(settings.ROLE_ADMIN, settings.ROLE_OPERADOR)),
):
    orden = db.get(Orden, payload.orden_id)
    if orden is None:
        raise HTTPException(404, "Orden no encontrada.")
    datos = payload.model_dump(exclude={"orden_id"})
    dispositivo = orden_service.agregar_dispositivo(db, orden, datos, actor_username=user["username"])
    db.commit()
    db.refresh(dispositivo)
    return dispositivo


@router.post("/hallazgo-casual", response_model=DispositivoRead, status_code=201)
def registrar_hallazgo_casual(
    payload: DispositivoHallazgoCasualCreate,
    db: Session = Depends(get_db),
    user: dict = Depends(require_role(settings.ROLE_ADMIN, settings.ROLE_OPERADOR)),
):
    orden = db.get(Orden, payload.orden_id)
    if orden is None:
        raise HTTPException(404, "Orden no encontrada.")
    dispositivo_origen = db.get(Dispositivo, payload.dispositivo_origen_id)
    if dispositivo_origen is None:
        raise HTTPException(404, "Dispositivo de origen no encontrado.")

    datos = payload.model_dump(exclude={"orden_id", "dispositivo_origen_id", "aprobado_por"})
    dispositivo = orden_service.registrar_hallazgo_casual(
        db, orden, dispositivo_origen, datos, actor_username=user["username"]
    )
    db.commit()
    db.refresh(dispositivo)
    return dispositivo


@router.post("/{dispositivo_id}/hallazgo-casual/aprobar", response_model=DispositivoRead)
def aprobar_hallazgo_casual(
    dispositivo_id: int,
    aprobado_por: str,
    db: Session = Depends(get_db),
    user: dict = Depends(require_role(settings.ROLE_ADMIN, settings.ROLE_OPERADOR)),
):
    dispositivo = db.get(Dispositivo, dispositivo_id)
    if dispositivo is None:
        raise HTTPException(404, "Dispositivo no encontrado.")
    try:
        dispositivo = orden_service.aprobar_hallazgo_casual(
            db, dispositivo, aprobado_por=aprobado_por, actor_username=user["username"]
        )
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    db.commit()
    db.refresh(dispositivo)
    return dispositivo


@router.post("/{dispositivo_id}/cese", response_model=DispositivoRead)
def ejecutar_cese(
    dispositivo_id: int,
    payload: DispositivoCeseRequest,
    db: Session = Depends(get_db),
    user: dict = Depends(require_role(settings.ROLE_ADMIN, settings.ROLE_OPERADOR)),
):
    dispositivo = db.get(Dispositivo, dispositivo_id)
    if dispositivo is None:
        raise HTTPException(404, "Dispositivo no encontrado.")
    try:
        dispositivo = cese_service.ejecutar_cese(
            db,
            dispositivo,
            ejecutado_por=payload.ejecutado_por,
            actor_username=user["username"],
            notas=payload.notas,
        )
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    db.commit()
    db.refresh(dispositivo)
    return dispositivo


@router.get("/{dispositivo_id}", response_model=DispositivoRead)
def obtener_dispositivo(dispositivo_id: int, db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    dispositivo = db.get(Dispositivo, dispositivo_id)
    if dispositivo is None:
        raise HTTPException(404, "Dispositivo no encontrado.")
    return dispositivo
