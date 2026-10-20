"""
Sharur SAIC - app/services/caso_service.py

Ciclo de vida del Caso: creacion y cierre (manual).
El cierre automatico y los controles de dispositivos quedan
reservados para fases posteriores.
"""

import json

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import sha256_of_text
from app.core.utils import utc_now
from app.models.auditoria import EventoAuditoria, TipoEvento
from app.models.caso import Caso, EstadoCaso
from app.services import auditoria_service


def crear_caso(db: Session, datos: dict, creado_por: str) -> Caso:
    """
    Crea un nuevo caso y lo firma en la cadena de auditoría.
    Captura errores de duplicidad (expediente u oficio) y los devuelve
    como ValueError para que la capa CLI muestre un mensaje legible.
    """
    caso = Caso(**datos, estado=EstadoCaso.ABIERTO, creado_por=creado_por)
    db.add(caso)
    
    try:
        db.flush()
    except IntegrityError as e:
        db.rollback()
        # Detectar si el conflicto fue por numero_causa o numero_oficio
        error_msg = str(e.orig)
        if "ix_casos_numero_causa" in error_msg:
            raise ValueError(f"Ya existe un caso con el expediente '{datos.get('numero_causa')}'.")
        elif "ix_casos_numero_oficio" in error_msg:
            raise ValueError(f"Ya existe un caso con el oficio '{datos.get('numero_oficio')}'.")
        else:
            raise ValueError("Error de integridad en la base de datos al crear el caso.")

    auditoria_service.registrar_evento(
        db,
        caso_id=caso.id,
        tipo_evento=TipoEvento.CASO_CREADO,
        descripcion=f"Caso '{caso.numero_causa}' creado.",
        actor_username=creado_por,
        detalle={"caratula": caso.caratula},
    )

    return caso


def _generar_reporte_final_hash(db: Session, caso: Caso) -> str:
    """
    Calcula el hash SHA-256 del resumen del caso para el cierre.
    Incluye la cantidad de eventos y el último hash de la cadena.
    """
    eventos = (
        db.query(EventoAuditoria)
        .filter(EventoAuditoria.caso_id == caso.id)
        .order_by(EventoAuditoria.secuencia.asc())
        .all()
    )
    resumen = {
        "caso_id": caso.id,
        "numero_causa": caso.numero_causa,
        "numero_oficio": caso.numero_oficio,
        "total_eventos": len(eventos),
        "ultimo_hash_evento": eventos[-1].hash_evento if eventos else None,
        "cerrado_en": utc_now().isoformat(),
    }
    return sha256_of_text(json.dumps(resumen, sort_keys=True))


def cerrar_caso(
    db: Session,
    caso: Caso,
    motivo_cierre: str,
    cerrado_por: str,
) -> Caso:
    """
    Cierra un caso. En el MVP no hay dispositivos ni gating, por lo
    que el cierre es directo: se registra el evento y se calcula el
    hash del reporte final.
    """
    caso.motivo_cierre = motivo_cierre
    caso.cerrado_por = cerrado_por
    caso.cerrado_en = utc_now()
    caso.estado = EstadoCaso.CERRADO_MANUAL

    auditoria_service.registrar_evento(
        db,
        caso_id=caso.id,
        tipo_evento=TipoEvento.CASO_CERRADO_MANUAL,
        descripcion=f"Caso cerrado manualmente: {motivo_cierre}",
        actor_username=cerrado_por,
        detalle={"motivo": motivo_cierre},
    )

    caso.hash_reporte_final = _generar_reporte_final_hash(db, caso)
    db.flush()

    return caso
