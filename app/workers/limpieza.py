"""
Sharur SAIC - app/workers/limpieza.py

Tareas asincronas asociadas al cese: verificacion de vencimiento
de ordenes y disparo de alertas para que el operador ejecute el
cese antes de que venza la ventana autorizada.

No ejecuta ningun mecanismo tecnico de desinstalacion remota
(ver services/cese_service.py para el detalle de ese limite).
Esta tarea es puramente de vigilancia temporal sobre datos ya
existentes en la base.
"""

from datetime import timedelta

from app.core.logging import logger
from app.core.utils import utc_now
from app.models.base import SessionLocal
from app.models.dispositivo import Dispositivo, EstadoDispositivo
from app.workers.celery_app import celery_app

VENTANA_ALERTA_HORAS = 24


@celery_app.task(name="limpieza.alertar_vencimientos_proximos")
def alertar_vencimientos_proximos() -> dict:
    """
    Tarea periodica (configurar en celery beat) que revisa
    dispositivos con orden proxima a vencer y sin cese ejecutado,
    para que el operador no llegue al vencimiento sin haber
    registrado el cese correspondiente.
    """
    db = SessionLocal()
    try:
        ahora = utc_now()
        limite = ahora + timedelta(hours=VENTANA_ALERTA_HORAS)

        dispositivos = (
            db.query(Dispositivo)
            .filter(Dispositivo.estado == EstadoDispositivo.AUTORIZADO_ACTIVO)
            .all()
        )

        alertas = []
        for dispositivo in dispositivos:
            orden = dispositivo.orden
            vencimiento = orden.prorroga_hasta or orden.vigente_hasta
            if vencimiento <= limite:
                alertas.append(
                    {
                        "dispositivo_id": dispositivo.id,
                        "identificador": dispositivo.identificador,
                        "orden_id": orden.id,
                        "vencimiento": vencimiento.isoformat(),
                    }
                )
                logger.warning(
                    "Ventana de orden %s vence pronto (%s) sin cese en dispositivo %s.",
                    orden.numero_orden,
                    vencimiento.isoformat(),
                    dispositivo.identificador,
                )

        return {"alertas_generadas": len(alertas), "detalle": alertas}
    finally:
        db.close()
