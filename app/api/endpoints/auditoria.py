"""
Sharur SAIC - app/api/endpoints/auditoria.py

Endpoints de consulta de auditoria, indexados por caso y por
dispositivo.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role, settings
from app.models.auditoria import EventoAuditoria
from app.schemas.auditoria import EventoAuditoriaRead

router = APIRouter(prefix="/api/v1/auditoria", tags=["auditoria"])


@router.get("/casos/{caso_id}", response_model=list[EventoAuditoriaRead])
def listar_eventos_por_caso(
    caso_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(require_role(settings.ROLE_ADMIN, settings.ROLE_OPERADOR)),
):
    return (
        db.query(EventoAuditoria)
        .filter(EventoAuditoria.caso_id == caso_id)
        .order_by(EventoAuditoria.secuencia.asc())
        .all()
    )


@router.get("/dispositivos/{dispositivo_id}", response_model=list[EventoAuditoriaRead])
def listar_eventos_por_dispositivo(
    dispositivo_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(require_role(settings.ROLE_ADMIN, settings.ROLE_OPERADOR)),
):
    return (
        db.query(EventoAuditoria)
        .filter(EventoAuditoria.dispositivo_id == dispositivo_id)
        .order_by(EventoAuditoria.secuencia.asc())
        .all()
    )
