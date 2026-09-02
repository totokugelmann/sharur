"""
Sharur SAIC - app/services/gating_service.py

Motor de gating: el punto de paso obligado para CUALQUIER accion
tecnica del sistema (herramientas automatizadas o consola manual).

Valida cada accion contra tres limites objetivos, en este orden:

1. DISPOSITIVO - el identificador esta en el alcance autorizado
   de una orden vigente para este caso, y su estado no es
   EXCLUIDO. Si es hallazgo casual, debe estar aprobado
   expresamente (Art. 286).
2. TIEMPO - la orden que ampara a ese dispositivo esta dentro de
   su ventana vigente_desde/vigente_hasta, o de la prorroga si
   existe y no vencio.
3. OPERADOR - el usuario que intenta la accion figura como
   PersonalAutorizado activo (no revocado) en la orden.

Si cualquiera de los tres falla: la accion se rechaza, se corta
la sesion (a nivel de la capa de API/consola que llama a este
servicio) y se registra un evento ACCION_RECHAZADA_GATING en la
auditoria con el detalle exacto de por que fallo.

Este servicio es deliberadamente "tonto" respecto al CONTENIDO de
la accion (que herramienta, que argumentos): eso es
responsabilidad de tools_service / consola. El gating solo
responde una pregunta: "¿esta accion, sobre este dispositivo, en
este momento, por este operador, esta autorizada?".
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.core.utils import ensure_aware_utc, utc_now
from app.models.dispositivo import Dispositivo, EstadoDispositivo
from app.models.orden import EstadoOrden, Orden, PersonalAutorizado


class MotivoRechazoGating:
    DISPOSITIVO_NO_ENCONTRADO = "dispositivo_no_encontrado"
    DISPOSITIVO_EXCLUIDO = "dispositivo_excluido"
    DISPOSITIVO_OBJETIVO_CUMPLIDO = "dispositivo_objetivo_cumplido"
    HALLAZGO_CASUAL_SIN_APROBAR = "hallazgo_casual_sin_aprobar"
    ORDEN_FUERA_DE_VENTANA = "orden_fuera_de_ventana"
    ORDEN_NO_VIGENTE = "orden_no_vigente"
    OPERADOR_NO_AUTORIZADO = "operador_no_autorizado"
    OPERADOR_REVOCADO = "operador_revocado"


@dataclass
class ResultadoGating:
    autorizado: bool
    motivo_rechazo: Optional[str] = None
    detalle: str = ""
    dispositivo: Optional[Dispositivo] = None
    orden: Optional[Orden] = None


def _validar_dispositivo(dispositivo: Optional[Dispositivo]) -> Optional[ResultadoGating]:
    if dispositivo is None:
        return ResultadoGating(
            autorizado=False,
            motivo_rechazo=MotivoRechazoGating.DISPOSITIVO_NO_ENCONTRADO,
            detalle="El identificador no corresponde a ningun dispositivo cargado en el sistema.",
        )

    if dispositivo.estado == EstadoDispositivo.EXCLUIDO:
        return ResultadoGating(
            autorizado=False,
            motivo_rechazo=MotivoRechazoGating.DISPOSITIVO_EXCLUIDO,
            detalle="El dispositivo fue removido del alcance autorizado.",
            dispositivo=dispositivo,
        )

    if dispositivo.estado == EstadoDispositivo.OBJETIVO_CUMPLIDO:
        return ResultadoGating(
            autorizado=False,
            motivo_rechazo=MotivoRechazoGating.DISPOSITIVO_OBJETIVO_CUMPLIDO,
            detalle="Ya se ejecuto el cese sobre este dispositivo; no se admiten nuevas acciones.",
            dispositivo=dispositivo,
        )

    if dispositivo.es_hallazgo_casual and not dispositivo.hallazgo_casual_aprobado_por:
        return ResultadoGating(
            autorizado=False,
            motivo_rechazo=MotivoRechazoGating.HALLAZGO_CASUAL_SIN_APROBAR,
            detalle=(
                "Dispositivo detectado como hallazgo casual (Art. 286) "
                "pendiente de inclusion expresa en la orden."
            ),
            dispositivo=dispositivo,
        )

    return None


def _validar_ventana_temporal(orden: Orden, ahora: datetime) -> Optional[ResultadoGating]:
    if orden.estado == EstadoOrden.CESADA:
        return ResultadoGating(
            autorizado=False,
            motivo_rechazo=MotivoRechazoGating.ORDEN_NO_VIGENTE,
            detalle="La orden fue cesada anticipadamente.",
            orden=orden,
        )

    vigente_desde = ensure_aware_utc(orden.vigente_desde)
    limite_superior = ensure_aware_utc(orden.prorroga_hasta if orden.prorroga_hasta else orden.vigente_hasta)
    ahora_aware = ensure_aware_utc(ahora)

    if ahora_aware < vigente_desde or ahora_aware > limite_superior:
        return ResultadoGating(
            autorizado=False,
            motivo_rechazo=MotivoRechazoGating.ORDEN_FUERA_DE_VENTANA,
            detalle=(
                f"Fuera de la ventana autorizada "
                f"({vigente_desde.isoformat()} - {limite_superior.isoformat()})."
            ),
            orden=orden,
        )

    return None


def _validar_operador(db: Session, orden_id: int, username: str) -> Optional[ResultadoGating]:
    personal = (
        db.query(PersonalAutorizado)
        .filter(
            PersonalAutorizado.orden_id == orden_id,
            PersonalAutorizado.username == username,
        )
        .first()
    )

    if personal is None:
        return ResultadoGating(
            autorizado=False,
            motivo_rechazo=MotivoRechazoGating.OPERADOR_NO_AUTORIZADO,
            detalle=f"El usuario '{username}' no figura como personal autorizado de esta orden.",
        )

    if personal.revocado_en is not None:
        return ResultadoGating(
            autorizado=False,
            motivo_rechazo=MotivoRechazoGating.OPERADOR_REVOCADO,
            detalle=f"La autorizacion de '{username}' fue revocada: {personal.revocado_motivo or 'sin motivo registrado'}.",
        )

    return None


def evaluar_gating(
    db: Session,
    dispositivo_id: int,
    username: str,
) -> ResultadoGating:
    """
    Punto de entrada unico del motor de gating.

    Se debe llamar ANTES de ejecutar cualquier accion tecnica,
    tanto desde las herramientas automatizadas como desde la
    consola manual. El llamador es responsable de:
    - no ejecutar nada si autorizado=False
    - registrar el resultado (positivo o negativo) en auditoria_service
    """
    ahora = utc_now()

    dispositivo = db.get(Dispositivo, dispositivo_id)

    resultado_dispositivo = _validar_dispositivo(dispositivo)
    if resultado_dispositivo is not None:
        return resultado_dispositivo

    orden = dispositivo.orden

    resultado_tiempo = _validar_ventana_temporal(orden, ahora)
    if resultado_tiempo is not None:
        resultado_tiempo.dispositivo = dispositivo
        return resultado_tiempo

    resultado_operador = _validar_operador(db, orden.id, username)
    if resultado_operador is not None:
        resultado_operador.dispositivo = dispositivo
        resultado_operador.orden = orden
        return resultado_operador

    return ResultadoGating(
        autorizado=True,
        detalle="Accion autorizada: dispositivo, ventana temporal y operador validados.",
        dispositivo=dispositivo,
        orden=orden,
    )
