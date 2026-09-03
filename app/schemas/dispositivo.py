"""
Sharur SAIC - app/schemas/dispositivo.py

Esquemas Pydantic para el recurso Dispositivo.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.dispositivo import EstadoDispositivo, TipoDispositivo


class DispositivoCreate(BaseModel):
    orden_id: int
    tipo: TipoDispositivo
    identificador: str = Field(..., max_length=512)
    rango_red_autorizado: Optional[str] = Field(
        None,
        max_length=128,
        description="Rango de red (CIDR) autorizado para localizar el dispositivo cuando su IP es dinámica.",
    )
    descripcion: Optional[str] = None
    sub_alcance_datos: str = Field(..., min_length=5)


class DispositivoHallazgoCasualCreate(BaseModel):
    """
    Alta de un dispositivo detectado como hallazgo casual (Art. 286).
    Requiere aprobacion expresa antes de poder operarse sobre el
    (ver gating_service.py).
    """

    orden_id: int
    tipo: TipoDispositivo
    identificador: str = Field(..., max_length=512)
    rango_red_autorizado: Optional[str] = Field(None, max_length=128)
    descripcion: Optional[str] = None
    sub_alcance_datos: str = Field(..., min_length=5)
    dispositivo_origen_id: int
    aprobado_por: str = Field(..., max_length=256)


class DispositivoRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    orden_id: int
    tipo: TipoDispositivo
    identificador: str
    rango_red_autorizado: Optional[str]
    descripcion: Optional[str]
    sub_alcance_datos: str
    estado: EstadoDispositivo
    es_hallazgo_casual: bool
    hallazgo_casual_origen_dispositivo_id: Optional[int]
    hallazgo_casual_aprobado_por: Optional[str]
    creado_en: datetime
    cese_ejecutado: bool
    cese_fecha: Optional[datetime]
    cese_ejecutado_por: Optional[str]
    cese_hash_verificacion: Optional[str]


class DispositivoCeseRequest(BaseModel):
    ejecutado_por: str = Field(..., max_length=128)
    notas: Optional[str] = None
