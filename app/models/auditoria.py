"""
Sharur SAIC - app/models/auditoria.py

Modelo de auditoria con hash encadenado (tamper-evident log).

Cada EventoAuditoria incluye el hash del evento anterior dentro
del mismo caso. Esto significa que modificar o borrar un evento
pasado rompe la cadena de hashes de todos los eventos
posteriores, haciendo la alteracion detectable -- propiedad
central para que el registro sea defendible como prueba.

Este modelo registra TODO: acciones exitosas, acciones
rechazadas por el gating, cambios de alcance, cese, notificacion,
cierre. Ver services/auditoria_service.py para la logica de
encadenado y verificacion.
"""

import enum

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.utils import utc_now
from app.models.base import Base


class TipoEvento(str, enum.Enum):
    CASO_CREADO = "caso_creado"
    ORDEN_CARGADA = "orden_cargada"
    DISPOSITIVO_AGREGADO = "dispositivo_agregado"
    ACCION_AUTORIZADA = "accion_autorizada"
    ACCION_RECHAZADA_GATING = "accion_rechazada_gating"
    HALLAZGO_IA_PROPUESTO = "hallazgo_ia_propuesto"
    HALLAZGO_VALIDADO = "hallazgo_validado"
    HALLAZGO_DESCARTADO = "hallazgo_descartado"
    HALLAZGO_CASUAL_DETECTADO = "hallazgo_casual_detectado"
    HALLAZGO_CASUAL_APROBADO = "hallazgo_casual_aprobado"
    CESE_EJECUTADO = "cese_ejecutado"
    NOTIFICACION_GENERADA = "notificacion_generada"
    SESION_CORTADA = "sesion_cortada"
    CASO_CERRADO_MANUAL = "caso_cerrado_manual"
    CASO_CERRADO_AUTOMATICO = "caso_cerrado_automatico"


class EventoAuditoria(Base):
    __tablename__ = "eventos_auditoria"

    id: Mapped[int] = mapped_column(primary_key=True)

    caso_id: Mapped[int] = mapped_column(ForeignKey("casos.id"), index=True)
    dispositivo_id: Mapped[int] = mapped_column(ForeignKey("dispositivos.id"), nullable=True, index=True)

    # Secuencia estrictamente creciente dentro del caso (base del encadenado)
    secuencia: Mapped[int] = mapped_column(Integer, index=True)

    tipo_evento: Mapped[TipoEvento] = mapped_column(Enum(TipoEvento), index=True)

    actor_username: Mapped[str] = mapped_column(String(128), nullable=True)
    descripcion: Mapped[str] = mapped_column(Text)

    # Payload estructurado (JSON serializado como texto) con el detalle
    # completo del evento: comando ejecutado, resultado del gating,
    # cita de evidencia, CVE validado, etc.
    detalle_json: Mapped[str] = mapped_column(Text, nullable=True)

    timestamp: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), default=utc_now)

    # Representacion ISO-8601 exacta usada para calcular el hash.
    # Se persiste de forma independiente de la columna `timestamp`
    # porque algunos backends/drivers (notablemente SQLite) pueden
    # perder el tzinfo al recargar un DateTime tras un commit,
    # cambiando el resultado de .isoformat() y produciendo falsos
    # positivos de "alteracion" al reverificar la cadena. Hashear
    # siempre sobre este string fijo evita depender de la fidelidad
    # del roundtrip del tipo DateTime en cada motor de base de datos.
    timestamp_iso: Mapped[str] = mapped_column(String(64))

    # ── Cadena de hashes ──────────────────────────────────────────
    hash_evento_anterior: Mapped[str] = mapped_column(String(64), nullable=True)
    hash_evento: Mapped[str] = mapped_column(String(64), index=True)

    caso: Mapped["Caso"] = relationship(back_populates="eventos_auditoria")
