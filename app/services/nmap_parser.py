"""
Sharur SAIC - app/services/nmap_parser.py

Parseo determinista de la salida de nmap (-sV). Extrae, por cada puerto
abierto, el servicio, el producto y la version, mas las lineas de scripts
('|' / '|_') que le pertenecen.

Sirve para dos cosas:
  1. Buscar CVEs en la NVD por producto+version SIN depender de que el
     LLM "recuerde" el identificador.
  2. Armar una evidencia compacta y limpia para el LLM (sin ruido de
     certificados, fechas ni host keys).
"""

import re
from dataclasses import dataclass, field
from typing import Optional

_PUERTO_RE = re.compile(r"^(\d+)/(tcp|udp)\s+open(?:\|filtered)?\s+(\S+)\s*(.*)$")
_VERSION_RE = re.compile(r"^v?\d")
_RUIDO = ("ssl-cert", "Not valid", "ssl-date", "ssh-hostkey", "clock-skew", "fingerprint")

MAX_EXTRAS_POR_PUERTO = 8


@dataclass
class PuertoNmap:
    puerto: int
    protocolo: str
    servicio: str
    producto: str = ""
    version: str = ""
    linea: str = ""
    extras: list[str] = field(default_factory=list)

    @property
    def bloque(self) -> str:
        return "\n".join([self.linea] + self.extras)


def _separar_producto_version(resto: str) -> tuple[str, str]:
    """'Apache httpd 2.2.8 ((Ubuntu) DAV/2)' -> ('Apache httpd', '2.2.8')."""
    tokens = resto.split()
    for i, tok in enumerate(tokens):
        if _VERSION_RE.match(tok):
            return " ".join(tokens[:i]).strip(), tok
    return " ".join(tokens).strip(), ""


def parsear_nmap(salida: str) -> list[PuertoNmap]:
    puertos: list[PuertoNmap] = []
    actual: Optional[PuertoNmap] = None

    for crudo in salida.splitlines():
        linea = crudo.rstrip()
        m = _PUERTO_RE.match(linea.strip())
        if m:
            numero, proto, servicio, resto = m.groups()
            producto, version = _separar_producto_version(resto)
            actual = PuertoNmap(
                puerto=int(numero), protocolo=proto, servicio=servicio,
                producto=producto, version=version, linea=linea.strip(),
            )
            puertos.append(actual)
            continue

        if actual is not None and linea.lstrip().startswith("|"):
            if any(r in linea for r in _RUIDO):
                continue
            if len(actual.extras) < MAX_EXTRAS_POR_PUERTO:
                actual.extras.append(linea.strip())
            continue

        # Cualquier otra linea (host nuevo, MAC, resumen) corta el bloque.
        if not linea.strip() or not linea.lstrip().startswith("|"):
            actual = None

    return puertos


def evidencia_compacta(puertos: list[PuertoNmap]) -> str:
    return "PUERTOS ABIERTOS:\n" + "\n".join(p.bloque for p in puertos)
