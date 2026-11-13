"""
Sharur SAIC - app/models/hallazgo.py
"""

import enum
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.utils import utc_now
from app.models.base import Base

if TYPE_CHECKING:
    from app.models.dispositivo import Dispositivo

class SeveridadHallazgo(str, enum.Enum):
    CRITICA = "critica"
    ALTA = "alta"
    MEDIA = "media"
    BAJA = "baja"
    INFORMATIVA = "informativa"


class ConfianzaHallazgo(str, enum.Enum):
    CONFIRMADA = "confirmada"
    PROBABLE = "probable"
    DESCARTADA = "descartada"


class Hallazgo(Base):
    __tablename__ = "hallazgos"

    id: Mapped[int] = mapped_column(primary_key=True)

    # Vínculo con el Caso (OBLIGATORIO)
    caso_id: Mapped[int] = mapped_column(ForeignKey("casos.id"), nullable=False)

    # Vínculo con el Dispositivo (Opcional)
    dispositivo_id: Mapped[Optional[int]] = mapped_column(ForeignKey("dispositivos.id"), nullable=True)

    herramienta_origen: Mapped[str] = mapped_column(String(64))
    comando_ejecutado: Mapped[str] = mapped_column(String(512))
    
    cve_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    titulo: Mapped[str] = mapped_column(String(256))
    descripcion: Mapped[str] = mapped_column(Text)
    
    cita_evidencia: Mapped[str] = mapped_column(Text)
    evidencia_cruda_hash: Mapped[str] = mapped_column(String(64))

    severidad: Mapped[SeveridadHallazgo] = mapped_column(Enum(SeveridadHallazgo), default=SeveridadHallazgo.INFORMATIVA)
    confianza: Mapped[ConfianzaHallazgo] = mapped_column(Enum(ConfianzaHallazgo), default=ConfianzaHallazgo.DESCARTADA)
    
    nvd_verificado: Mapped[bool] = mapped_column(default=False)
    nvd_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    creado_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    # Relación inversa (soluciona el error de SQLAlchemy)
    dispositivo: Mapped[Optional["Dispositivo"]] = relationship(back_populates="hallazgos")
