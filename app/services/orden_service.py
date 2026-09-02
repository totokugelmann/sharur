"""
Sharur SAIC - app/services/orden_service.py

Gestion de ordenes judiciales, su alcance de dispositivos, y el
flujo de hallazgo casual (Art. 286 CPP Misiones).

Principio de diseno: nada de esto ejecuta acciones tecnicas. Solo
administra el estado que despues gating_service usa para decidir
si una accion tecnica se autoriza.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.core.utils import normalize_target, utc_now
from app.models.auditoria import TipoEvento
from app.models.dispositivo import Dispositivo, EstadoDispositivo, TipoDispositivo
from app.models.orden import EstadoOrden, Orden, PersonalAutorizado
from app.services import auditoria_service, network_control


def crear_orden(db: Session, caso_id: int, datos: dict, actor_username: str) -> Orden:
    orden = Orden(caso_id=caso_id, **datos, estado=EstadoOrden.VIGENTE)
    db.add(orden)
    db.flush()

    auditoria_service.registrar_evento(
        db,
        caso_id=caso_id,
        tipo_evento=TipoEvento.ORDEN_CARGADA,
        descripcion=f"Orden '{orden.numero_orden}' cargada.",
        actor_username=actor_username,
        detalle={"orden_id": orden.id, "numero_orden": orden.numero_orden},
    )

    network_control.inicializar_perimetro_caso(caso_id)

    return orden


def prorrogar_orden(db: Session, orden: Orden, nueva_fecha_hasta: datetime, autorizada_por: str, actor_username: str) -> Orden:
    orden.prorroga_hasta = nueva_fecha_hasta
    orden.prorroga_autorizada_por = autorizada_por
    orden.prorroga_fecha = utc_now()
    orden.estado = EstadoOrden.PRORROGADA
    db.flush()

    auditoria_service.registrar_evento(
        db,
        caso_id=orden.caso_id,
        tipo_evento=TipoEvento.ORDEN_CARGADA,
        descripcion=f"Orden '{orden.numero_orden}' prorrogada hasta {nueva_fecha_hasta.isoformat()}.",
        actor_username=actor_username,
        detalle={"orden_id": orden.id, "autorizada_por": autorizada_por},
    )
    return orden


def agregar_personal_autorizado(db: Session, orden: Orden, datos: dict, actor_username: str) -> PersonalAutorizado:
    personal = PersonalAutorizado(orden_id=orden.id, **datos)
    db.add(personal)
    db.flush()

    auditoria_service.registrar_evento(
        db,
        caso_id=orden.caso_id,
        tipo_evento=TipoEvento.ORDEN_CARGADA,
        descripcion=f"Personal autorizado agregado: {personal.username} ({personal.rol_funcional}).",
        actor_username=actor_username,
        detalle={"orden_id": orden.id, "personal_id": personal.id},
    )
    return personal


def revocar_personal_autorizado(db: Session, personal: PersonalAutorizado, motivo: str, actor_username: str) -> PersonalAutorizado:
    personal.revocado_en = utc_now()
    personal.revocado_motivo = motivo
    db.flush()

    auditoria_service.registrar_evento(
        db,
        caso_id=personal.orden.caso_id,
        tipo_evento=TipoEvento.ORDEN_CARGADA,
        descripcion=f"Autorizacion revocada para {personal.username}: {motivo}",
        actor_username=actor_username,
        detalle={"personal_id": personal.id},
    )
    return personal


def agregar_dispositivo(db: Session, orden: Orden, datos: dict, actor_username: str) -> Dispositivo:
    identificador = datos["identificador"]
    dispositivo = Dispositivo(
        orden_id=orden.id,
        estado=EstadoDispositivo.AUTORIZADO_ACTIVO,
        identificador_normalizado=normalize_target(identificador),
        **datos,
    )
    db.add(dispositivo)
    db.flush()

    auditoria_service.registrar_evento(
        db,
        caso_id=orden.caso_id,
        tipo_evento=TipoEvento.DISPOSITIVO_AGREGADO,
        descripcion=f"Dispositivo '{identificador}' agregado al alcance de la orden '{orden.numero_orden}'.",
        actor_username=actor_username,
        dispositivo_id=dispositivo.id,
        detalle={"tipo": dispositivo.tipo.value, "identificador": identificador},
    )

    # Amplia el perimetro de red del caso si el identificador es IP/CIDR
    network_control.permitir_destino(orden.caso_id, identificador)

    return dispositivo


def registrar_hallazgo_casual(
    db: Session,
    orden: Orden,
    dispositivo_origen: Dispositivo,
    datos: dict,
    actor_username: str,
) -> Dispositivo:
    """
    Registra un nuevo dispositivo detectado incidentalmente
    durante una intervencion ya en curso (Art. 286). Queda en
    estado PENDIENTE hasta que se aprueba expresamente -- el
    gating lo bloquea mientras tanto (ver gating_service:
    HALLAZGO_CASUAL_SIN_APROBAR).
    """
    identificador = datos["identificador"]
    dispositivo = Dispositivo(
        orden_id=orden.id,
        estado=EstadoDispositivo.PENDIENTE,
        identificador_normalizado=normalize_target(identificador),
        es_hallazgo_casual=True,
        hallazgo_casual_origen_dispositivo_id=dispositivo_origen.id,
        **datos,
    )
    db.add(dispositivo)
    db.flush()

    auditoria_service.registrar_evento(
        db,
        caso_id=orden.caso_id,
        tipo_evento=TipoEvento.HALLAZGO_CASUAL_DETECTADO,
        descripcion=(
            f"Hallazgo casual detectado: '{identificador}', originado desde "
            f"dispositivo id={dispositivo_origen.id}. Pendiente de aprobacion expresa (Art. 286)."
        ),
        actor_username=actor_username,
        dispositivo_id=dispositivo.id,
        detalle={"dispositivo_origen_id": dispositivo_origen.id},
    )

    return dispositivo


def aprobar_hallazgo_casual(db: Session, dispositivo: Dispositivo, aprobado_por: str, actor_username: str) -> Dispositivo:
    if not dispositivo.es_hallazgo_casual:
        raise ValueError("El dispositivo no esta marcado como hallazgo casual.")

    dispositivo.hallazgo_casual_aprobado_por = aprobado_por
    dispositivo.hallazgo_casual_fecha_aprobacion = utc_now()
    dispositivo.estado = EstadoDispositivo.AUTORIZADO_ACTIVO
    db.flush()

    auditoria_service.registrar_evento(
        db,
        caso_id=dispositivo.orden.caso_id,
        tipo_evento=TipoEvento.HALLAZGO_CASUAL_APROBADO,
        descripcion=f"Hallazgo casual sobre '{dispositivo.identificador}' aprobado por {aprobado_por}.",
        actor_username=actor_username,
        dispositivo_id=dispositivo.id,
        detalle={"aprobado_por": aprobado_por},
    )

    network_control.permitir_destino(dispositivo.orden.caso_id, dispositivo.identificador)

    return dispositivo


def excluir_dispositivo(db: Session, dispositivo: Dispositivo, motivo: str, actor_username: str) -> Dispositivo:
    dispositivo.estado = EstadoDispositivo.EXCLUIDO
    db.flush()

    auditoria_service.registrar_evento(
        db,
        caso_id=dispositivo.orden.caso_id,
        tipo_evento=TipoEvento.DISPOSITIVO_AGREGADO,
        descripcion=f"Dispositivo '{dispositivo.identificador}' excluido del alcance: {motivo}",
        actor_username=actor_username,
        dispositivo_id=dispositivo.id,
        detalle={"motivo": motivo},
    )

    network_control.revocar_destino(dispositivo.orden.caso_id, dispositivo.identificador)

    return dispositivo
