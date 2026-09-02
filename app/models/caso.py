"""
Sharur SAIC - app/models/caso.py

Modelo de Caso: la causa judicial dentro de la cual se emite una
o mas ordenes con su alcance autorizado.

Un caso es el contenedor de mayor nivel. No habilita ninguna
accion tecnica por si solo: la habilitacion real vive en Orden +
Dispositivo (ver orden.py, dispositivo.py).
"""

import enum

from sqlalchemy import Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.utils import utc_now
from app.models.base import Base
from sqlalchemy import DateTime


class EstadoCaso(str, enum.Enum):
    ABIERTO = "abierto"
    EN_CURSO = "en_curso"
    CERRADO_MANUAL = "cerrado_manual"
    CERRADO_AUTOMATICO = "cerrado_automatico"  # por expulsion / vencimiento


class Caso(Base):
    __tablename__ = "casos"

    id: Mapped[int] = mapped_column(primary_key=True)

    # Identificacion de la causa judicial
    numero_causa: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    caratula: Mapped[str] = mapped_column(String(512))
    juzgado_interviniente: Mapped[str] = mapped_column(String(256))
    fiscalia_interviniente: Mapped[str] = mapped_column(String(256), nullable=True)

    descripcion: Mapped[str] = mapped_column(Text, nullable=True)

    estado: Mapped[EstadoCaso] = mapped_column(
        Enum(EstadoCaso), default=EstadoCaso.ABIERTO, nullable=False
    )

    creado_por: Mapped[str] = mapped_column(String(128))
    creado_en: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), default=utc_now)

    cerrado_en: Mapped["DateTime"] = mapped_column(DateTime(timezone=True), nullable=True)
    cerrado_por: Mapped[str] = mapped_column(String(128), nullable=True)
    motivo_cierre: Mapped[str] = mapped_column(Text, nullable=True)

    # Hash de integridad del reporte final (se completa al cierre)
    hash_reporte_final: Mapped[str] = mapped_column(String(64), nullable=True)

    ordenes: Mapped[list["Orden"]] = relationship(
        back_populates="caso", cascade="all, delete-orphan"
    )
    eventos_auditoria: Mapped[list["EventoAuditoria"]] = relationship(
        back_populates="caso", cascade="all, delete-orphan"
    )

    # Nota: las relaciones usan forward refs (strings). Todos los modelos
    # se registran de forma centralizada en app/models/__init__.py para
    # que SQLAlchemy pueda resolverlas sin imports circulares aca.
