"""
Sharur SAIC - app/models/__init__.py

Registro centralizado de todos los modelos SQLAlchemy.

Importar este paquete (por ejemplo desde app/main.py antes de
crear las tablas o correr Alembic) garantiza que todas las
relaciones declaradas con forward-refs (strings) se resuelvan
correctamente, sin depender de imports circulares dentro de cada
archivo de modelo.
"""

from app.models.base import Base  # noqa: F401
from app.models.caso import Caso, EstadoCaso  # noqa: F401
from app.models.orden import Orden, EstadoOrden, PersonalAutorizado  # noqa: F401
from app.models.dispositivo import Dispositivo, TipoDispositivo, EstadoDispositivo  # noqa: F401
from app.models.auditoria import EventoAuditoria, TipoEvento  # noqa: F401
from app.models.notificacion import (  # noqa: F401
    Notificacion,
    EstadoNotificacion,
    Hallazgo,
    SeveridadHallazgo,
    ConfianzaHallazgo,
)

__all__ = [
    "Base",
    "Caso",
    "EstadoCaso",
    "Orden",
    "EstadoOrden",
    "PersonalAutorizado",
    "Dispositivo",
    "TipoDispositivo",
    "EstadoDispositivo",
    "EventoAuditoria",
    "TipoEvento",
    "Notificacion",
    "EstadoNotificacion",
    "Hallazgo",
    "SeveridadHallazgo",
    "ConfianzaHallazgo",
]
