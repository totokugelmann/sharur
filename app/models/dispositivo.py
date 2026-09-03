"""
Sharur SAIC - app/models/dispositivo.py

Modelo de Dispositivo: cada target concreto habilitado por una
Orden, con su propio sub-alcance de datos.

Este es el nivel mas granular de autorizacion. El gating_service
valida CADA accion tecnica contra la fila de Dispositivo
correspondiente: si el identificador no esta acá, la accion se
rechaza sin excepcion, incluso si pertenece al mismo imputado
(hallazgo casual, Art. 286 -> requiere alta expresa de un nuevo
Dispositivo antes de poder actuar sobre el).
"""

import enum

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.utils import utc_now
from app.models.base import Base


class TipoDispositivo(str, enum.Enum):
    HOST_RED = "host_red"          # IP / dominio, reconocimiento de red-servicios
    API_BACKEND = "api_backend"
    DISPOSITIVO_MOVIL = "dispositivo_movil"
    OTRO = "otro"


class EstadoDispositivo(str, enum.Enum):
    PENDIENTE = "pendiente"          # cargado pero fuera de ventana / sin iniciar
    AUTORIZADO_ACTIVO = "autorizado_activo"
    OBJETIVO_CUMPLIDO = "objetivo_cumplido"  # cese ejecutado en este dispositivo
    EXCLUIDO = "excluido"            # removido del alcance (error, revocacion, etc.)


class Dispositivo(Base):
    __tablename__ = "dispositivos"

    id: Mapped[int] = mapped_column(primary_key=True)
    orden_id: Mapped[int] = mapped_column(ForeignKey("ordenes.id"), index=True)

    tipo: Mapped[TipoDispositivo] = mapped_column(Enum(TipoDispositivo))

    # Identificador tecnico del target: IP, dominio, IMEI, modelo del
    # dispositivo, etc. Es el dato DESCRIPTIVO/de referencia -- no
    # necesariamente la IP exacta a usar en cada escaneo, porque en la
    # gran mayoria de los casos (celulares, notebooks) la IP es
    # dinamica y se desconoce de antemano.
    identificador: Mapped[str] = mapped_column(String(512), index=True)
    identificador_normalizado: Mapped[str] = mapped_column(String(512), index=True)

    # Rango de red autorizado para LOCALIZAR este dispositivo cuando
    # su IP exacta se desconoce de antemano (ej: "192.168.1.0/24").
    # Es lo que la orden habilita a escanear para encontrar el
    # dispositivo, no una promesa de que el sistema pueda verificar
    # automaticamente que el equipo hallado en ese rango es
    # efectivamente el autorizado (eso depende de MAC/hostname/
    # fingerprint, que se pueden falsear) -- esa correlacion final
    # queda a cargo del operador, revisando manualmente la evidencia
    # y los logs de auditoria despues del escaneo. Opcional: si el
    # dispositivo tiene una IP fija conocida, puede omitirse y usar
    # directamente `identificador` como objetivo.
    rango_red_autorizado: Mapped[str] = mapped_column(String(128), nullable=True)

    descripcion: Mapped[str] = mapped_column(Text, nullable=True)

    # Sub-alcance de datos autorizados sobre ESTE dispositivo
    # especificamente (ej: "solo metadatos de comunicaciones",
    # "contenido de mensajeria X", "servicios de red expuestos").
    sub_alcance_datos: Mapped[str] = mapped_column(Text)

    estado: Mapped[EstadoDispositivo] = mapped_column(
        Enum(EstadoDispositivo), default=EstadoDispositivo.PENDIENTE, nullable=False
    )

    # Si este dispositivo se incorporo por hallazgo casual (Art. 286)
    es_hallazgo_casual: Mapped[bool] = mapped_column(Boolean, default=False)
    hallazgo_casual_origen_dispositivo_id: Mapped[int] = mapped_column(
        ForeignKey("dispositivos.id"), nullable=True
    )
    hallazgo_casual_aprobado_por: Mapped[str] = mapped_column(String(256), nullable=True)
    hallazgo_casual_fecha_aprobacion: Mapped["DateTime"] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    creado_en: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), default=utc_now)

    # ── Cese y eliminacion (por dispositivo, pueden ser momentos distintos) ──
    cese_ejecutado: Mapped[bool] = mapped_column(Boolean, default=False)
    cese_fecha: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), nullable=True)
    cese_ejecutado_por: Mapped[str] = mapped_column(String(128), nullable=True)
    cese_hash_verificacion: Mapped[str] = mapped_column(String(64), nullable=True)
    cese_notas: Mapped[str] = mapped_column(Text, nullable=True)

    orden: Mapped["Orden"] = relationship(back_populates="dispositivos")
    hallazgos: Mapped[list["Hallazgo"]] = relationship(
        back_populates="dispositivo", cascade="all, delete-orphan"
    )
    notificaciones: Mapped[list["Notificacion"]] = relationship(
        back_populates="dispositivo", cascade="all, delete-orphan"
    )
