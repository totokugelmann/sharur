"""
Sharur SAIC - app/schemas/caso.py

Esquemas Pydantic para el recurso Caso.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.caso import EstadoCaso


class CasoCreate(BaseModel):
    numero_causa: str = Field(..., max_length=128)
    caratula: str = Field(..., max_length=512)
    juzgado_interviniente: str = Field(..., max_length=256)
    fiscalia_interviniente: Optional[str] = Field(None, max_length=256)
    descripcion: Optional[str] = None


class CasoRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    numero_causa: str
    caratula: str
    juzgado_interviniente: str
    fiscalia_interviniente: Optional[str]
    descripcion: Optional[str]
    estado: EstadoCaso
    creado_por: str
    creado_en: datetime
    cerrado_en: Optional[datetime]
    cerrado_por: Optional[str]
    motivo_cierre: Optional[str]
    hash_reporte_final: Optional[str]


class CasoCierre(BaseModel):
    motivo_cierre: str
    forzado: bool = False  # True si es cierre automatico por expulsion
