"""
Sharur SAIC - app/core/utils.py

Utilidades generales compartidas entre servicios.
"""

import ipaddress
import re
from datetime import datetime, timezone
from typing import Optional


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def ensure_aware_utc(value: datetime) -> datetime:
    """
    Normaliza un datetime a timezone-aware UTC.

    Algunos backends/drivers (notablemente SQLite) pueden devolver
    datetimes "naive" (sin tzinfo) al recargar una fila desde la
    base, incluso si la columna se declaro como DateTime(timezone=True)
    y el valor original si tenia tzinfo. Comparar un datetime naive
    contra uno aware lanza TypeError, y en el peor caso (silenciosa
    asuncion de horario local) podria introducir errores de calculo
    en las ventanas temporales que gating_service usa para autorizar
    o rechazar una accion -- algo inaceptable en este modulo.

    Esta funcion se debe usar antes de cualquier comparacion de
    datetimes que involucre valores potencialmente recargados desde
    la base de datos.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def is_valid_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value))


def normalize_target(value: str) -> str:
    """Normaliza un identificador de dispositivo/target para comparaciones consistentes."""
    return value.strip().lower()


def safe_slug(value: str) -> str:
    """Convierte un string arbitrario en un slug seguro para nombres de archivo/carpeta."""
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", value.strip())
    return slug.strip("_") or "sin_nombre"


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
