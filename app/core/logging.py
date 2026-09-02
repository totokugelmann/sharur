"""
Sharur SAIC - app/core/logging.py

Configuracion de logging seguro.

Principios:
- Nunca loguear tokens, passwords, ni contenido crudo de evidencia
  (la evidencia tiene su propio circuito de auditoria en
  services/auditoria_service.py, con hash encadenado).
- Los logs de aplicacion son para operacion/debug, no para cadena
  de custodia. No reemplazan la auditoria forense.
- Rotacion diaria, retencion configurable.
"""

import logging
import os
from logging.handlers import TimedRotatingFileHandler

from app.core.config import get_settings

settings = get_settings()

_SENSITIVE_KEYS = {"password", "token", "secret", "authorization", "access_token"}


class RedactSensitiveFilter(logging.Filter):
    """Redacta valores de claves sensibles si aparecen en el mensaje formateado."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        lowered = msg.lower()
        for key in _SENSITIVE_KEYS:
            if key in lowered:
                record.msg = "[REDACTED - posible contenido sensible en log]"
                record.args = ()
                break
        return True


def configure_logging() -> logging.Logger:
    os.makedirs(settings.LOG_DIR, exist_ok=True)

    logger = logging.getLogger("sharur_saic")
    logger.setLevel(settings.LOG_LEVEL)

    if logger.handlers:
        return logger  # ya configurado (evita duplicar handlers en reload)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    file_handler = TimedRotatingFileHandler(
        filename=os.path.join(settings.LOG_DIR, "sharur_saic.log"),
        when="midnight",
        backupCount=90,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.addFilter(RedactSensitiveFilter())

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.addFilter(RedactSensitiveFilter())

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


logger = configure_logging()
