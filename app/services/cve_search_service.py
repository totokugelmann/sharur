"""
Sharur SAIC - app/services/cve_search_service.py

Busqueda y verificacion de CVEs contra fuente autoritativa (NVD).

Adaptado del search.py original de Sharur: mantiene el bloqueo de
terminos de explotacion en las consultas (nunca se busca "exploit
for CVE-XXXX", solo informacion descriptiva/de mitigacion), y
agrega la verificacion estructurada contra la API de NVD que
antes no existia.

Este modulo NO decide si un hallazgo es valido: solo responde
"¿este CVE existe, y que dice la fuente autoritativa sobre el?".
La decision de aceptar/rechazar/degradar un hallazgo vive en
analisis_ia_service.py.
"""

import re
import time
from dataclasses import dataclass
from typing import Optional

import requests

from app.core.config import get_settings
from app.core.logging import logger

settings = get_settings()

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

_BLOCKED_TERMS = [
    "exploit for",
    "exploit-db",
    "metasploit module",
    "poc exploit",
    "rce payload",
    "reverse shell",
    "download exploit",
]


def is_cve(value: str) -> bool:
    return bool(_CVE_RE.match(value.strip()))


def blocked_query_reason(query: str) -> Optional[str]:
    lowered = query.lower()
    for term in _BLOCKED_TERMS:
        if term in lowered:
            return f"La consulta contiene un termino bloqueado: '{term}'."
    return None


@dataclass
class ResultadoVerificacionCVE:
    existe: bool
    cve_id: str
    descripcion: str = ""
    cvss_score: Optional[float] = None
    severidad_nvd: Optional[str] = None
    fuente: str = "NVD"
    error: Optional[str] = None


def verificar_cve_en_nvd(cve_id: str, max_reintentos: int = 2) -> ResultadoVerificacionCVE:
    """
    Consulta la API publica de NVD para confirmar que un CVE
    existe y traer su score/severidad oficial.

    Este es el paso que reemplaza la confianza ciega en lo que
    el LLM "cree" que es un CVE valido.
    """
    if not is_cve(cve_id):
        return ResultadoVerificacionCVE(
            existe=False, cve_id=cve_id, error="Formato de CVE invalido."
        )

    headers = {}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    params = {"cveId": cve_id.upper()}

    for intento in range(max_reintentos + 1):
        try:
            resp = requests.get(
                settings.NVD_API_URL, params=params, headers=headers, timeout=15
            )
        except requests.RequestException as exc:
            logger.warning("Fallo consultando NVD para %s (intento %s): %s", cve_id, intento, exc)
            time.sleep(1.5 * (intento + 1))
            continue

        if resp.status_code == 429:
            time.sleep(2.0 * (intento + 1))
            continue

        if resp.status_code != 200:
            return ResultadoVerificacionCVE(
                existe=False,
                cve_id=cve_id,
                error=f"NVD respondio status {resp.status_code}",
            )

        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return ResultadoVerificacionCVE(existe=False, cve_id=cve_id, error="CVE no encontrado en NVD.")

        cve_data = vulnerabilities[0].get("cve", {})
        descripciones = cve_data.get("descriptions", [])
        descripcion_en = next(
            (d["value"] for d in descripciones if d.get("lang") == "en"), ""
        )

        metrics = cve_data.get("metrics", {})
        cvss_score = None
        severidad = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severidad = metrics[key][0].get("baseSeverity", cvss_data.get("baseSeverity"))
                break

        return ResultadoVerificacionCVE(
            existe=True,
            cve_id=cve_id,
            descripcion=descripcion_en,
            cvss_score=cvss_score,
            severidad_nvd=severidad,
        )

    return ResultadoVerificacionCVE(
        existe=False, cve_id=cve_id, error="No se pudo contactar a NVD tras reintentos."
    )
