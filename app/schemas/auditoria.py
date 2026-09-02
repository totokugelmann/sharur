"""
Sharur SAIC - app/schemas/auditoria.py

Esquemas Pydantic para auditoria, hallazgos y notificaciones.
"""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict

from app.models.auditoria import TipoEvento
from app.models.notificacion import ConfianzaHallazgo, EstadoNotificacion, SeveridadHallazgo


class EventoAuditoriaRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    caso_id: int
    dispositivo_id: Optional[int]
    secuencia: int
    tipo_evento: TipoEvento
    actor_username: Optional[str]
    descripcion: str
    detalle_json: Optional[str]
    timestamp: datetime
    timestamp_iso: str
    hash_evento_anterior: Optional[str]
    hash_evento: str


class VerificacionCadenaResponse(BaseModel):
    caso_id: int
    total_eventos: int
    integra: bool
    primer_evento_alterado: Optional[int] = None
    detalle: str


class HallazgoRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    dispositivo_id: int
    herramienta_origen: str
    comando_ejecutado: str
    cve_id: Optional[str]
    titulo: str
    descripcion: str
    cita_evidencia: str
    severidad: SeveridadHallazgo
    confianza: ConfianzaHallazgo
    nvd_verificado: bool
    nvd_score: Optional[float]
    creado_en: datetime


class NotificacionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    dispositivo_id: int
    estado: EstadoNotificacion
    destinatario_nombre: str
    destinatario_rol: str
    contenido: str
    generada_en: datetime
    enviada_en: Optional[datetime]
    hash_contenido: str


class AnalisisIARequest(BaseModel):
    dispositivo_id: int
    herramienta: str  # ej: "nmap", "httpx"
    parametros: Dict[str, Any] = {}


class ConsolaComandoRequest(BaseModel):
    """
    Comando de la consola manual. `binario` debe estar en la
    allow-list de settings.CONSOLE_ALLOWED_BINARIES; `argumentos`
    se pasa como lista (nunca como string a un shell).
    """

    dispositivo_id: int
    binario: str
    argumentos: list[str] = []
    notas: Optional[str] = None
