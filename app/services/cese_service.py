"""
Sharur SAIC - app/services/cese_service.py

Registro de cese por dispositivo.

IMPORTANTE - alcance deliberado de este modulo: registra el
EVENTO de cese (quien lo ejecuto, cuando, con que hash de
verificacion, notas) como parte de la cadena de auditoria y
custodia. NO implementa un mecanismo tecnico de
desinstalacion/limpieza remota de ningun agente -- ese mecanismo,
si existe, es una pieza externa y separada que se invoca antes de
llamar a este servicio; aca solo se dejan asentadas sus
consecuencias auditables:

  [algo externo ejecuta la limpieza tecnica en el dispositivo]
        -> devuelve un hash/comprobante de verificacion
        -> este servicio registra ese comprobante y cierra el
           dispositivo para nuevas acciones (gating lo bloquea
           en adelante, ver EstadoDispositivo.OBJETIVO_CUMPLIDO)

Tras el cese, tambien se revoca el permiso de red del dispositivo
en el perimetro del caso.
"""

from typing import Optional

from sqlalchemy.orm import Session

from app.core.security import sha256_of_text
from app.core.utils import utc_now
from app.models.auditoria import TipoEvento
from app.models.dispositivo import Dispositivo, EstadoDispositivo
from app.services import auditoria_service, network_control


def ejecutar_cese(
    db: Session,
    dispositivo: Dispositivo,
    ejecutado_por: str,
    actor_username: str,
    notas: Optional[str] = None,
    comprobante_externo: Optional[str] = None,
) -> Dispositivo:
    """
    Registra el cese de una intervencion sobre un dispositivo
    especifico.

    `comprobante_externo` es opcional: si el mecanismo tecnico de
    limpieza (externo a este sistema) provee algun comprobante o
    log de verificacion, se hashea junto con los metadatos del
    cese para dejar constancia verificable sin que este sistema
    necesite conocer los detalles tecnicos de como se logro.
    """
    if dispositivo.cese_ejecutado:
        raise ValueError("El cese ya fue registrado previamente para este dispositivo.")

    contenido_hash = sha256_of_text(
        f"{dispositivo.id}|{ejecutado_por}|{utc_now().isoformat()}|{comprobante_externo or ''}"
    )

    dispositivo.cese_ejecutado = True
    dispositivo.cese_fecha = utc_now()
    dispositivo.cese_ejecutado_por = ejecutado_por
    dispositivo.cese_hash_verificacion = contenido_hash
    dispositivo.cese_notas = notas
    dispositivo.estado = EstadoDispositivo.OBJETIVO_CUMPLIDO
    db.flush()

    auditoria_service.registrar_evento(
        db,
        caso_id=dispositivo.orden.caso_id,
        tipo_evento=TipoEvento.CESE_EJECUTADO,
        descripcion=f"Cese registrado sobre dispositivo '{dispositivo.identificador}'.",
        actor_username=actor_username,
        dispositivo_id=dispositivo.id,
        detalle={
            "ejecutado_por": ejecutado_por,
            "hash_verificacion": contenido_hash,
            "notas": notas,
        },
    )

    network_control.revocar_destino(dispositivo.orden.caso_id, dispositivo.identificador)
    if dispositivo.rango_red_autorizado:
        network_control.revocar_destino(dispositivo.orden.caso_id, dispositivo.rango_red_autorizado)

    return dispositivo


def todos_los_dispositivos_cesados(db: Session, orden_id_list: list[int]) -> bool:
    """Utilidad para el cierre de caso: confirma que no queden dispositivos activos sin cese."""
    from app.models.dispositivo import Dispositivo as D

    pendientes = (
        db.query(D)
        .filter(
            D.orden_id.in_(orden_id_list),
            D.estado == EstadoDispositivo.AUTORIZADO_ACTIVO,
        )
        .count()
    )
    return pendientes == 0
