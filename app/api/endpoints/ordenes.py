"""
Sharur SAIC - app/api/endpoints/ordenes.py

Endpoints de ordenes judiciales, personal autorizado y prorroga.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, require_role, settings
from app.models.orden import Orden, PersonalAutorizado
from app.schemas.orden import (
    OrdenCreate,
    OrdenProrroga,
    OrdenRead,
    PersonalAutorizadoCreate,
    PersonalAutorizadoRead,
)
from app.services import orden_service

router = APIRouter(prefix="/api/v1/ordenes", tags=["ordenes"])


@router.post("", response_model=OrdenRead, status_code=201)
def crear_orden(
    payload: OrdenCreate,
    db: Session = Depends(get_db),
    user: dict = Depends(require_role(settings.ROLE_ADMIN, settings.ROLE_OPERADOR)),
):
    datos = payload.model_dump(exclude={"caso_id"})
    orden = orden_service.crear_orden(db, caso_id=payload.caso_id, datos=datos, actor_username=user["username"])
    db.commit()
    db.refresh(orden)
    return orden


@router.get("/{orden_id}", response_model=OrdenRead)
def obtener_orden(orden_id: int, db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    orden = db.get(Orden, orden_id)
    if orden is None:
        raise HTTPException(404, "Orden no encontrada.")
    return orden


@router.post("/{orden_id}/prorroga", response_model=OrdenRead)
def prorrogar_orden(
    orden_id: int,
    payload: OrdenProrroga,
    db: Session = Depends(get_db),
    user: dict = Depends(require_role(settings.ROLE_ADMIN, settings.ROLE_OPERADOR)),
):
    orden = db.get(Orden, orden_id)
    if orden is None:
        raise HTTPException(404, "Orden no encontrada.")
    orden = orden_service.prorrogar_orden(
        db, orden, payload.nueva_fecha_hasta, payload.autorizada_por, actor_username=user["username"]
    )
    db.commit()
    db.refresh(orden)
    return orden


@router.post("/{orden_id}/personal", response_model=PersonalAutorizadoRead, status_code=201)
def agregar_personal(
    orden_id: int,
    payload: PersonalAutorizadoCreate,
    db: Session = Depends(get_db),
    user: dict = Depends(require_role(settings.ROLE_ADMIN, settings.ROLE_OPERADOR)),
):
    orden = db.get(Orden, orden_id)
    if orden is None:
        raise HTTPException(404, "Orden no encontrada.")
    personal = orden_service.agregar_personal_autorizado(
        db, orden, payload.model_dump(), actor_username=user["username"]
    )
    db.commit()
    db.refresh(personal)
    return personal


@router.delete("/personal/{personal_id}", response_model=PersonalAutorizadoRead)
def revocar_personal(
    personal_id: int,
    motivo: str,
    db: Session = Depends(get_db),
    user: dict = Depends(require_role(settings.ROLE_ADMIN, settings.ROLE_OPERADOR)),
):
    personal = db.get(PersonalAutorizado, personal_id)
    if personal is None:
        raise HTTPException(404, "Personal no encontrado.")
    personal = orden_service.revocar_personal_autorizado(db, personal, motivo, actor_username=user["username"])
    db.commit()
    db.refresh(personal)
    return personal
