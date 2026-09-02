"""
Sharur SAIC - app/schemas/orden.py

Esquemas Pydantic para el recurso Orden (orden judicial + alcance).

Los campos de fundamentacion (proporcionalidad/necesidad/idoneidad)
son obligatorios en la creacion: el Art. 285 CPP Misiones exige
esta fundamentacion bajo pena de nulidad, asi que el sistema no
permite cargar una orden sin ella.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.orden import EstadoOrden


class OrdenCreate(BaseModel):
    caso_id: int
    numero_orden: str = Field(..., max_length=128)
    juez_firmante: str = Field(..., max_length=256)
    fecha_emision: datetime

    vigente_desde: datetime
    vigente_hasta: datetime

    fundamento_proporcionalidad: str = Field(..., min_length=10)
    fundamento_necesidad: str = Field(..., min_length=10)
    fundamento_idoneidad: str = Field(..., min_length=10)

    imputado_identificacion: str = Field(..., max_length=512)
    defensor_nombre: Optional[str] = None
    defensor_contacto: Optional[str] = None

    @model_validator(mode="after")
    def validar_ventana_temporal(self) -> "OrdenCreate":
        if self.vigente_hasta <= self.vigente_desde:
            raise ValueError("vigente_hasta debe ser posterior a vigente_desde")
        return self


class OrdenProrroga(BaseModel):
    nueva_fecha_hasta: datetime
    autorizada_por: str = Field(..., max_length=256)


class OrdenRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    caso_id: int
    numero_orden: str
    juez_firmante: str
    fecha_emision: datetime
    vigente_desde: datetime
    vigente_hasta: datetime
    prorroga_hasta: Optional[datetime]
    prorroga_autorizada_por: Optional[str]
    fundamento_proporcionalidad: str
    fundamento_necesidad: str
    fundamento_idoneidad: str
    imputado_identificacion: str
    defensor_nombre: Optional[str]
    defensor_contacto: Optional[str]
    estado: EstadoOrden
    creado_en: datetime


class PersonalAutorizadoCreate(BaseModel):
    username: str = Field(..., max_length=128)
    nombre_completo: str = Field(..., max_length=256)
    legajo: Optional[str] = None
    rol_funcional: str = Field(..., max_length=128)


class PersonalAutorizadoRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    orden_id: int
    username: str
    nombre_completo: str
    legajo: Optional[str]
    rol_funcional: str
    autorizado_desde: datetime
    revocado_en: Optional[datetime]
    revocado_motivo: Optional[str]
