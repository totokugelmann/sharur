"""
Sharur SAIC - app/services/notificacion_service.py

Generacion y seguimiento de notificaciones al imputado/defensor,
exigencia del Art. 285 CPP Misiones.

El contenido de la notificacion se arma automaticamente a partir
de los datos ya registrados en la Orden y el Dispositivo (fechas,
alcance, fundamento), para evitar que la notificacion dependa de
que alguien la redacte a mano y omita algo.
"""

from sqlalchemy.orm import Session

from app.core.security import sha256_of_text
from app.core.utils import utc_now
from app.models.auditoria import TipoEvento
from app.models.dispositivo import Dispositivo
from app.models.notificacion import EstadoNotificacion, Notificacion
from app.services import auditoria_service


def _armar_contenido(dispositivo: Dispositivo) -> str:
    orden = dispositivo.orden
    return (
        f"NOTIFICACION DE INTERVENCION TECNICA - Causa {orden.caso.numero_causa}\n"
        f"Orden judicial: {orden.numero_orden}, emitida por {orden.juez_firmante} "
        f"el {orden.fecha_emision.date().isoformat()}.\n"
        f"Dispositivo/objetivo: {dispositivo.identificador} ({dispositivo.tipo.value}).\n"
        f"Alcance de datos autorizado: {dispositivo.sub_alcance_datos}\n"
        f"Periodo de vigencia: {orden.vigente_desde.date().isoformat()} a "
        f"{(orden.prorroga_hasta or orden.vigente_hasta).date().isoformat()}.\n"
        f"Cese ejecutado: {dispositivo.cese_fecha.isoformat() if dispositivo.cese_fecha else 'pendiente'}.\n"
        f"Fundamento de proporcionalidad: {orden.fundamento_proporcionalidad}\n"
        f"Fundamento de necesidad: {orden.fundamento_necesidad}\n"
        f"Fundamento de idoneidad: {orden.fundamento_idoneidad}\n"
        f"Se notifica de conformidad con el Art. 285 del Codigo Procesal Penal "
        f"de Misiones (Ley XIV N° 13)."
    )


def generar_notificacion(
    db: Session,
    dispositivo: Dispositivo,
    destinatario_nombre: str,
    destinatario_rol: str,
    actor_username: str,
) -> Notificacion:
    contenido = _armar_contenido(dispositivo)
    hash_contenido = sha256_of_text(contenido)

    notificacion = Notificacion(
        dispositivo_id=dispositivo.id,
        estado=EstadoNotificacion.GENERADA,
        destinatario_nombre=destinatario_nombre,
        destinatario_rol=destinatario_rol,
        contenido=contenido,
        hash_contenido=hash_contenido,
    )
    db.add(notificacion)
    db.flush()

    auditoria_service.registrar_evento(
        db,
        caso_id=dispositivo.orden.caso_id,
        tipo_evento=TipoEvento.NOTIFICACION_GENERADA,
        descripcion=f"Notificacion generada para {destinatario_rol} '{destinatario_nombre}'.",
        actor_username=actor_username,
        dispositivo_id=dispositivo.id,
        detalle={"notificacion_id": notificacion.id, "hash_contenido": hash_contenido},
    )

    return notificacion


def marcar_enviada(db: Session, notificacion: Notificacion) -> Notificacion:
    notificacion.estado = EstadoNotificacion.ENVIADA
    notificacion.enviada_en = utc_now()
    db.flush()
    return notificacion


def marcar_acuse_recibido(db: Session, notificacion: Notificacion) -> Notificacion:
    notificacion.estado = EstadoNotificacion.ACUSE_RECIBIDO
    notificacion.acuse_en = utc_now()
    db.flush()
    return notificacion
