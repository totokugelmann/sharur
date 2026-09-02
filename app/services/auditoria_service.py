"""
Sharur SAIC - app/services/auditoria_service.py

Registro de eventos de auditoria con hash encadenado, y
verificacion de integridad de la cadena.

Cada evento incluye:
- su numero de secuencia dentro del caso
- el hash del evento inmediatamente anterior (o None si es el primero)
- su propio hash, calculado sobre (secuencia + tipo + actor +
  descripcion + detalle + timestamp + hash_evento_anterior)

Esto crea una cadena tipo blockchain simplificada: alterar
cualquier campo de un evento pasado cambia su hash, lo cual
invalida el hash_evento_anterior de todos los eventos
posteriores. verificar_cadena() recorre toda la cadena y detecta
el primer punto de ruptura, si existe.
"""

import hashlib
import json
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.core.utils import utc_now
from app.models.auditoria import EventoAuditoria, TipoEvento


def _calcular_hash_evento(
    secuencia: int,
    tipo_evento: str,
    actor_username: Optional[str],
    descripcion: str,
    detalle_json: Optional[str],
    timestamp_iso: str,
    hash_evento_anterior: Optional[str],
) -> str:
    payload = json.dumps(
        {
            "secuencia": secuencia,
            "tipo_evento": tipo_evento,
            "actor_username": actor_username,
            "descripcion": descripcion,
            "detalle_json": detalle_json,
            "timestamp": timestamp_iso,
            "hash_evento_anterior": hash_evento_anterior,
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def registrar_evento(
    db: Session,
    caso_id: int,
    tipo_evento: TipoEvento,
    descripcion: str,
    actor_username: Optional[str] = None,
    dispositivo_id: Optional[int] = None,
    detalle: Optional[Dict[str, Any]] = None,
) -> EventoAuditoria:
    """
    Registra un nuevo evento de auditoria, encadenandolo al
    ultimo evento existente para el caso.

    Debe llamarse dentro de la misma transaccion que la accion que
    se esta auditando cuando sea posible, para evitar huecos entre
    "la accion ocurrio" y "quedo registrada".
    """
    ultimo_evento = (
        db.query(EventoAuditoria)
        .filter(EventoAuditoria.caso_id == caso_id)
        .order_by(EventoAuditoria.secuencia.desc())
        .first()
    )

    siguiente_secuencia = (ultimo_evento.secuencia + 1) if ultimo_evento else 1
    hash_anterior = ultimo_evento.hash_evento if ultimo_evento else None

    timestamp = utc_now()
    timestamp_iso = timestamp.isoformat()
    detalle_json = json.dumps(detalle, sort_keys=True, ensure_ascii=False) if detalle else None

    hash_evento = _calcular_hash_evento(
        secuencia=siguiente_secuencia,
        tipo_evento=tipo_evento.value,
        actor_username=actor_username,
        descripcion=descripcion,
        detalle_json=detalle_json,
        timestamp_iso=timestamp_iso,
        hash_evento_anterior=hash_anterior,
    )

    evento = EventoAuditoria(
        caso_id=caso_id,
        dispositivo_id=dispositivo_id,
        secuencia=siguiente_secuencia,
        tipo_evento=tipo_evento,
        actor_username=actor_username,
        descripcion=descripcion,
        detalle_json=detalle_json,
        timestamp=timestamp,
        timestamp_iso=timestamp_iso,
        hash_evento_anterior=hash_anterior,
        hash_evento=hash_evento,
    )

    db.add(evento)
    db.flush()  # asegura evento.id disponible sin cerrar la transaccion
    return evento


def verificar_cadena(db: Session, caso_id: int) -> Dict[str, Any]:
    """
    Recorre todos los eventos de un caso en orden de secuencia y
    recalcula cada hash para detectar alteraciones.

    Retorna un dict con:
    - integra: bool
    - total_eventos: int
    - primer_evento_alterado: Optional[int] (numero de secuencia)
    - detalle: str
    """
    eventos = (
        db.query(EventoAuditoria)
        .filter(EventoAuditoria.caso_id == caso_id)
        .order_by(EventoAuditoria.secuencia.asc())
        .all()
    )

    hash_anterior_esperado = None

    for evento in eventos:
        if evento.hash_evento_anterior != hash_anterior_esperado:
            return {
                "integra": False,
                "total_eventos": len(eventos),
                "primer_evento_alterado": evento.secuencia,
                "detalle": (
                    f"Rotura de cadena en secuencia {evento.secuencia}: "
                    f"hash_evento_anterior no coincide con el hash del evento previo."
                ),
            }

        hash_recalculado = _calcular_hash_evento(
            secuencia=evento.secuencia,
            tipo_evento=evento.tipo_evento.value if hasattr(evento.tipo_evento, "value") else evento.tipo_evento,
            actor_username=evento.actor_username,
            descripcion=evento.descripcion,
            detalle_json=evento.detalle_json,
            timestamp_iso=evento.timestamp_iso,
            hash_evento_anterior=evento.hash_evento_anterior,
        )

        if hash_recalculado != evento.hash_evento:
            return {
                "integra": False,
                "total_eventos": len(eventos),
                "primer_evento_alterado": evento.secuencia,
                "detalle": (
                    f"Hash recalculado no coincide con el hash almacenado en "
                    f"secuencia {evento.secuencia}: el contenido del evento fue alterado."
                ),
            }

        hash_anterior_esperado = evento.hash_evento

    return {
        "integra": True,
        "total_eventos": len(eventos),
        "primer_evento_alterado": None,
        "detalle": "Cadena de auditoria integra: ningun evento fue alterado.",
    }
