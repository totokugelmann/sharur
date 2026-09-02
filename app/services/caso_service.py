"""
Sharur SAIC - app/services/caso_service.py

Ciclo de vida del Caso: creacion y cierre (manual o automatico).

El cierre automatico se dispara desde gating_service/consola
cuando corresponda expulsar al operador (ver
services/expulsion.py si se agrega logica de umbral de intentos
fallidos); por ahora el disparo automatico se deja como funcion
explicita para que la capa API decida cuando invocarlo.
"""

import json
from typing import Optional

from sqlalchemy.orm import Session

from app.core.security import sha256_of_text
from app.core.utils import utc_now
from app.models.auditoria import EventoAuditoria, TipoEvento
from app.models.caso import Caso, EstadoCaso
from app.models.dispositivo import Dispositivo, EstadoDispositivo
from app.services import auditoria_service, network_control
from app.services.auditoria_service import verificar_cadena
from app.services.cese_service import todos_los_dispositivos_cesados


def crear_caso(db: Session, datos: dict, creado_por: str) -> Caso:
    caso = Caso(**datos, estado=EstadoCaso.ABIERTO, creado_por=creado_por)
    db.add(caso)
    db.flush()

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
    eventos = (
        db.query(EventoAuditoria)
        .filter(EventoAuditoria.caso_id == caso.id)
        .order_by(EventoAuditoria.secuencia.asc())
        .all()
    )
    resumen = {
        "caso_id": caso.id,
        "numero_causa": caso.numero_causa,
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
    forzado: bool = False,
) -> Caso:
    """
    Cierra un caso. Si `forzado` es False, exige que todos los
    dispositivos de todas las ordenes del caso tengan cese
    ejecutado antes de permitir el cierre -- un cierre "prolijo"
    no deberia dejar dispositivos con acceso activo.

    forzado=True se usa para el cierre automatico por expulsion:
    ahi la prioridad es cortar todo inmediatamente, y el estado
    de cada dispositivo queda auditado tal cual estaba.
    """
    orden_ids = [orden.id for orden in caso.ordenes]

    if not forzado and orden_ids and not todos_los_dispositivos_cesados(db, orden_ids):
        raise ValueError(
            "No se puede cerrar el caso: existen dispositivos con estado "
            "AUTORIZADO_ACTIVO sin cese ejecutado. Use forzado=True solo "
            "para cierre automatico por expulsion."
        )

    caso.motivo_cierre = motivo_cierre
    caso.cerrado_por = cerrado_por
    caso.cerrado_en = utc_now()
    caso.estado = EstadoCaso.CERRADO_AUTOMATICO if forzado else EstadoCaso.CERRADO_MANUAL

    tipo_evento = TipoEvento.CASO_CERRADO_AUTOMATICO if forzado else TipoEvento.CASO_CERRADO_MANUAL

    auditoria_service.registrar_evento(
        db,
        caso_id=caso.id,
        tipo_evento=tipo_evento,
        descripcion=f"Caso cerrado ({'automatico' if forzado else 'manual'}): {motivo_cierre}",
        actor_username=cerrado_por,
        detalle={"forzado": forzado},
    )

    caso.hash_reporte_final = _generar_reporte_final_hash(db, caso)
    db.flush()

    for orden_id in orden_ids:
        network_control.desmontar_perimetro_caso(caso.id)

    return caso


def cierre_automatico_por_expulsion(
    db: Session,
    caso: Caso,
    motivo_expulsion: str,
    actor_username: Optional[str],
) -> Caso:
    """
    Atajo semantico para el disparo automatico descripto en el
    flujo: cuando el gating corta una sesion, la capa API puede
    decidir escalar a cierre automatico de caso si la politica de
    la SAIC asi lo determina (por ejemplo, tras N rechazos).
    """
    auditoria_service.registrar_evento(
        db,
        caso_id=caso.id,
        tipo_evento=TipoEvento.SESION_CORTADA,
        descripcion=f"Sesion cortada por gating: {motivo_expulsion}",
        actor_username=actor_username,
        detalle={"motivo": motivo_expulsion},
    )
    return cerrar_caso(
        db,
        caso,
        motivo_cierre=f"Cierre automatico por expulsion: {motivo_expulsion}",
        cerrado_por=actor_username or "sistema",
        forzado=True,
    )
