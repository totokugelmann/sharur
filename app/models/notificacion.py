"""
Sharur SAIC - app/models/notificacion.py

Modelos de Notificacion (al imputado/defensor, exigencia del
Art. 285) y Hallazgo (resultado validado de una herramienta de
analisis o del pipeline evidence-first con IA).
"""

import enum

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.utils import utc_now
from app.models.base import Base


class EstadoNotificacion(str, enum.Enum):
    PENDIENTE = "pendiente"
    GENERADA = "generada"
    ENVIADA = "enviada"
    ACUSE_RECIBIDO = "acuse_recibido"


class Notificacion(Base):
    __tablename__ = "notificaciones"

    id: Mapped[int] = mapped_column(primary_key=True)
    dispositivo_id: Mapped[int] = mapped_column(ForeignKey("dispositivos.id"), index=True)

    estado: Mapped[EstadoNotificacion] = mapped_column(
        Enum(EstadoNotificacion), default=EstadoNotificacion.PENDIENTE
    )

    destinatario_nombre: Mapped[str] = mapped_column(String(256))
    destinatario_rol: Mapped[str] = mapped_column(String(64))  # "imputado" | "defensor"
    contenido: Mapped[str] = mapped_column(Text)

    generada_en: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), default=utc_now)
    enviada_en: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), nullable=True)
    acuse_en: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), nullable=True)

    hash_contenido: Mapped[str] = mapped_column(String(64))

    dispositivo: Mapped["Dispositivo"] = relationship(back_populates="notificaciones")


class SeveridadHallazgo(str, enum.Enum):
    CRITICA = "critica"
    ALTA = "alta"
    MEDIA = "media"
    BAJA = "baja"
    INFORMATIVA = "informativa"


class ConfianzaHallazgo(str, enum.Enum):
    CONFIRMADA = "confirmada"     # CVE verificado contra NVD + cita valida
    PROBABLE = "probable"         # cita valida pero CVE no pudo verificarse
    DESCARTADA = "descartada"     # cita no encontrada en evidencia cruda


class Hallazgo(Base):
    """
    Resultado del pipeline evidence-first: herramienta -> LLM propone
    -> validacion deterministica contra evidencia cruda y contra NVD.

    Solo lo que llega a CONFIRMADA o PROBABLE se considera hallazgo
    real; DESCARTADA se conserva para trazabilidad (que se le
    propuso al modelo y por que se rechazo).
    """

    __tablename__ = "hallazgos"

    id: Mapped[int] = mapped_column(primary_key=True)
    dispositivo_id: Mapped[int] = mapped_column(ForeignKey("dispositivos.id"), index=True)

    herramienta_origen: Mapped[str] = mapped_column(String(128))  # ej: "nmap"
    comando_ejecutado: Mapped[str] = mapped_column(Text)

    cve_id: Mapped[str] = mapped_column(String(32), nullable=True, index=True)
    titulo: Mapped[str] = mapped_column(String(512))
    descripcion: Mapped[str] = mapped_column(Text)

    cita_evidencia: Mapped[str] = mapped_column(Text)
    evidencia_cruda_hash: Mapped[str] = mapped_column(String(64))

    severidad: Mapped[SeveridadHallazgo] = mapped_column(Enum(SeveridadHallazgo))
    confianza: Mapped[ConfianzaHallazgo] = mapped_column(Enum(ConfianzaHallazgo))

    nvd_verificado: Mapped[bool] = mapped_column(default=False)
    nvd_score: Mapped[float] = mapped_column(Float, nullable=True)

    creado_en: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), default=utc_now)

    dispositivo: Mapped["Dispositivo"] = relationship(back_populates="hallazgos")
