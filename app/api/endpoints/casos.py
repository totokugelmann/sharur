"""
Sharur SAIC - app/api/endpoints/casos.py

Endpoints de gestion de Casos.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, require_role, settings
from app.models.caso import Caso
from app.schemas.auditoria import VerificacionCadenaResponse
from app.schemas.caso import CasoCierre, CasoCreate, CasoRead
from app.services import caso_service
from app.services.auditoria_service import verificar_cadena

router = APIRouter(prefix="/api/v1/casos", tags=["casos"])


@router.post("", response_model=CasoRead, status_code=201)
def crear_caso(
    payload: CasoCreate,
    db: Session = Depends(get_db),
    user: dict = Depends(require_role(settings.ROLE_ADMIN, settings.ROLE_OPERADOR)),
):
    caso = caso_service.crear_caso(db, payload.model_dump(), creado_por=user["username"])
    db.commit()
    db.refresh(caso)
    return caso


@router.get("/{caso_id}", response_model=CasoRead)
def obtener_caso(caso_id: int, db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    caso = db.get(Caso, caso_id)
    if caso is None:
        raise HTTPException(404, "Caso no encontrado.")
    return caso


@router.post("/{caso_id}/cerrar", response_model=CasoRead)
def cerrar_caso(
    caso_id: int,
    payload: CasoCierre,
    db: Session = Depends(get_db),
    user: dict = Depends(require_role(settings.ROLE_ADMIN, settings.ROLE_OPERADOR)),
):
    caso = db.get(Caso, caso_id)
    if caso is None:
        raise HTTPException(404, "Caso no encontrado.")
    try:
        caso = caso_service.cerrar_caso(
            db, caso, motivo_cierre=payload.motivo_cierre, cerrado_por=user["username"], forzado=payload.forzado
        )
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    db.commit()
    db.refresh(caso)
    return caso


@router.get("/{caso_id}/auditoria/verificar", response_model=VerificacionCadenaResponse)
def verificar_integridad_auditoria(
    caso_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(require_role(settings.ROLE_ADMIN, settings.ROLE_OPERADOR)),
):
    resultado = verificar_cadena(db, caso_id)
    return VerificacionCadenaResponse(caso_id=caso_id, **resultado)
