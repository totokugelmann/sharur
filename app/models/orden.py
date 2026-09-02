"""
Sharur SAIC - app/models/orden.py

Modelo de Orden judicial: el objeto que efectivamente habilita
una intervencion tecnica.

Cumple el requisito del Art. 285 CPP Misiones: la orden debe
detallar personal interviniente, duracion, alcance, y prorroga
posible, bajo pena de nulidad. Estos campos NO son opcionales
por diseno.

Nada se ejecuta hasta que existe una Orden con al menos un
Dispositivo asociado y su ventana temporal vigente (ver
gating_service.py, que es quien realmente hace cumplir esto en
tiempo de ejecucion).
"""

import enum

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.utils import utc_now
from app.models.base import Base


class EstadoOrden(str, enum.Enum):
    VIGENTE = "vigente"
    PRORROGADA = "prorrogada"
    VENCIDA = "vencida"
    CESADA = "cesada"  # cese anticipado por cumplimiento de objetivo


class Orden(Base):
    __tablename__ = "ordenes"

    id: Mapped[int] = mapped_column(primary_key=True)

    caso_id: Mapped[int] = mapped_column(ForeignKey("casos.id"), index=True)

    # ── Identificacion de la orden judicial ──────────────────────
    numero_orden: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    juez_firmante: Mapped[str] = mapped_column(String(256))
    fecha_emision: Mapped["DateTime"] = mapped_column(DateTime(timezone=True))

    # ── Ventana temporal (Art. 285: duracion + prorroga) ─────────
    vigente_desde: Mapped["DateTime"] = mapped_column(DateTime(timezone=True))
    vigente_hasta: Mapped["DateTime"] = mapped_column(DateTime(timezone=True))

    prorroga_hasta: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), nullable=True)
    prorroga_autorizada_por: Mapped[str] = mapped_column(String(256), nullable=True)
    prorroga_fecha: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), nullable=True)

    # ── Fundamentacion exigida por el Art. 285 ───────────────────
    fundamento_proporcionalidad: Mapped[str] = mapped_column(Text)
    fundamento_necesidad: Mapped[str] = mapped_column(Text)
    fundamento_idoneidad: Mapped[str] = mapped_column(Text)

    # ── Datos del imputado / defensor (para notificacion) ────────
    imputado_identificacion: Mapped[str] = mapped_column(String(512))
    defensor_nombre: Mapped[str] = mapped_column(String(256), nullable=True)
    defensor_contacto: Mapped[str] = mapped_column(String(256), nullable=True)

    estado: Mapped[EstadoOrden] = mapped_column(
        Enum(EstadoOrden), default=EstadoOrden.VIGENTE, nullable=False
    )

    creado_en: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), default=utc_now)

    caso: Mapped["Caso"] = relationship(back_populates="ordenes")
    dispositivos: Mapped[list["Dispositivo"]] = relationship(
        back_populates="orden", cascade="all, delete-orphan"
    )
    personal_autorizado: Mapped[list["PersonalAutorizado"]] = relationship(
        back_populates="orden", cascade="all, delete-orphan"
    )


class PersonalAutorizado(Base):
    """
    Personal interviniente habilitado a operar sobre esta orden
    (exigencia expresa del Art. 285). El gating_service valida
    contra esta tabla en cada accion, no solo contra el rol
    generico de la API.
    """

    __tablename__ = "personal_autorizado"

    id: Mapped[int] = mapped_column(primary_key=True)
    orden_id: Mapped[int] = mapped_column(ForeignKey("ordenes.id"), index=True)

    username: Mapped[str] = mapped_column(String(128), index=True)
    nombre_completo: Mapped[str] = mapped_column(String(256))
    legajo: Mapped[str] = mapped_column(String(64), nullable=True)
    rol_funcional: Mapped[str] = mapped_column(String(128))  # ej: "perito", "operador tecnico"

    autorizado_desde: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), default=utc_now)
    revocado_en: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), nullable=True)
    revocado_motivo: Mapped[str] = mapped_column(Text, nullable=True)

    orden: Mapped["Orden"] = relationship(back_populates="personal_autorizado")
