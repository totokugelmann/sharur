"""
Sharur SAIC - app/services/cve_search_service.py

Busqueda y verificacion de CVEs contra fuente autoritativa (NVD).

Adaptado del search.py original de Sharur: mantiene el bloqueo de
terminos de explotacion en las consultas (nunca se busca "exploit
for CVE-XXXX", solo informacion descriptiva/de mitigacion), y
agrega la verificacion estructurada contra la API de NVD que
antes no existia.

Estados posibles de una consulta (ver ESTADO_*):
  - verificado          la NVD respondio y el CVE existe.
  - no_existe           la NVD respondio y el CVE no existe.
  - nvd_no_disponible   la NVD no respondio (red, 429, 5xx): NO significa
                        que el CVE no exista; el hallazgo queda sin verificar.

Ademas de verificar un CVE por ID, busca CVEs por producto+version
(buscar_cves_por_producto): es la via determinista; el LLM no tiene que
recordar ningun identificador.

Este modulo NO decide si un hallazgo es valido: solo responde
"¿este CVE existe, y que dice la fuente autoritativa sobre el?".
La decision de aceptar/rechazar/degradar un hallazgo vive en
analisis_ia_service.py.
"""

import json
import os
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


ESTADO_VERIFICADO = "verificado"
ESTADO_NO_EXISTE = "no_existe"
ESTADO_NO_DISPONIBLE = "nvd_no_disponible"

_ultimo_request = 0.0


def _dormir(segundos: float) -> None:
    time.sleep(segundos)


def _throttle() -> None:
    """Respeta el rate limit publico de NVD (5 req/30s sin API key)."""
    global _ultimo_request
    minimo = 0.7 if settings.NVD_API_KEY else 6.5
    espera = minimo - (time.monotonic() - _ultimo_request)
    if espera > 0 and _ultimo_request:
        _dormir(espera)
    _ultimo_request = time.monotonic()


# ── Cache local (solo respuestas exitosas de NVD) ───────────────────
def _cache_leer(clave: str):
    try:
        with open(settings.NVD_CACHE_PATH, encoding="utf-8") as fh:
            entrada = json.load(fh).get(clave)
    except (OSError, ValueError):
        return None
    if not entrada:
        return None
    if time.time() - entrada.get("ts", 0) > settings.NVD_CACHE_TTL_HORAS * 3600:
        return None
    return entrada.get("data")


def _cache_escribir(clave: str, data) -> None:
    try:
        try:
            with open(settings.NVD_CACHE_PATH, encoding="utf-8") as fh:
                cache = json.load(fh)
        except (OSError, ValueError):
            cache = {}
        cache[clave] = {"ts": time.time(), "data": data}
        carpeta = os.path.dirname(settings.NVD_CACHE_PATH)
        if carpeta:
            os.makedirs(carpeta, exist_ok=True)
        with open(settings.NVD_CACHE_PATH, "w", encoding="utf-8") as fh:
            json.dump(cache, fh)
    except OSError as exc:
        logger.warning("No se pudo escribir el cache de NVD: %s", exc)


def _consultar_nvd(params: dict, max_reintentos: int = 3):
    """
    GET a NVD con reintentos ante errores de red, 429 y 5xx.
    Devuelve (json | None, error | None). Usa cache en disco.
    """
    clave = json.dumps(params, sort_keys=True)
    en_cache = _cache_leer(clave)
    if en_cache is not None:
        return en_cache, None

    headers = {"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else {}
    ultimo_error = "sin respuesta"

    for intento in range(max_reintentos + 1):
        _throttle()
        try:
            resp = requests.get(settings.NVD_API_URL, params=params, headers=headers, timeout=30)
        except requests.RequestException as exc:
            ultimo_error = f"error de red: {exc}"
            logger.warning("NVD intento %s: %s", intento, ultimo_error)
            _dormir(2.0 * (intento + 1))
            continue

        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                ultimo_error = "NVD devolvio una respuesta no JSON"
                _dormir(2.0 * (intento + 1))
                continue
            _cache_escribir(clave, data)
            return data, None

        ultimo_error = f"NVD respondio status {resp.status_code}"
        if resp.status_code == 429 or resp.status_code >= 500:
            logger.warning("NVD intento %s: %s", intento, ultimo_error)
            _dormir(3.0 * (intento + 1))
            continue
        return None, ultimo_error  # 4xx distinto de 429: no tiene sentido reintentar

    return None, ultimo_error


def _extraer_cvss(cve_data: dict) -> tuple[Optional[float], Optional[str]]:
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            cvss = m.get("cvssData", {})
            return cvss.get("baseScore"), m.get("baseSeverity", cvss.get("baseSeverity"))
    return None, None


def _descripcion_en(cve_data: dict) -> str:
    return next((d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"), "")


@dataclass
class ResultadoVerificacionCVE:
    existe: bool
    cve_id: str
    descripcion: str = ""
    cvss_score: Optional[float] = None
    severidad_nvd: Optional[str] = None
    fuente: str = "NVD"
    error: Optional[str] = None
    estado: str = ESTADO_NO_EXISTE


def verificar_cve_en_nvd(cve_id: str, max_reintentos: int = 3) -> ResultadoVerificacionCVE:
    """
    Confirma que un CVE existe y trae su score oficial.
    Distingue 'no existe' de 'NVD no disponible'.
    """
    if not is_cve(cve_id):
        return ResultadoVerificacionCVE(
            existe=False, cve_id=cve_id, error="Formato de CVE invalido.", estado=ESTADO_NO_EXISTE
        )

    data, error = _consultar_nvd({"cveId": cve_id.upper()}, max_reintentos)
    if data is None:
        return ResultadoVerificacionCVE(
            existe=False, cve_id=cve_id, error=error, estado=ESTADO_NO_DISPONIBLE
        )

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return ResultadoVerificacionCVE(
            existe=False, cve_id=cve_id, error="CVE no encontrado en NVD.", estado=ESTADO_NO_EXISTE
        )

    cve_data = vulns[0].get("cve", {})
    score, sev = _extraer_cvss(cve_data)
    return ResultadoVerificacionCVE(
        existe=True, cve_id=cve_id.upper(), descripcion=_descripcion_en(cve_data),
        cvss_score=score, severidad_nvd=sev, estado=ESTADO_VERIFICADO,
    )


# ── Busqueda por producto + version ─────────────────────────────────
def _version_tuple(v: str) -> tuple:
    """'4.7p1' -> (4, 7); '5.0.51a-3ubuntu5' -> (5, 0, 51)."""
    m = re.match(r"v?(\d+(?:\.\d+)*)", v.strip())
    return tuple(int(x) for x in m.group(1).split(".")) if m else ()


def version_afectada(version: str, cpe_match: dict) -> bool:
    """¿La version instalada cae dentro de lo que declara este cpeMatch de NVD?"""
    v = _version_tuple(version)
    if not v:
        return False
    partes = cpe_match.get("criteria", "").split(":")
    v_cpe = partes[5] if len(partes) > 5 else "*"
    if v_cpe == "-":
        return False
    if v_cpe not in ("*", ""):
        return _version_tuple(v_cpe) == v

    rangos = [
        ("versionStartIncluding", lambda a, b: a >= b),
        ("versionStartExcluding", lambda a, b: a > b),
        ("versionEndIncluding", lambda a, b: a <= b),
        ("versionEndExcluding", lambda a, b: a < b),
    ]
    for campo, cmp in rangos:
        if campo in cpe_match and not cmp(v, _version_tuple(cpe_match[campo])):
            return False
    return True


def _coincide_producto(producto: str, cpe_match: dict) -> bool:
    partes = cpe_match.get("criteria", "").split(":")
    if len(partes) < 5:
        return False
    prod_l = producto.lower()
    nombres = [partes[3].replace("_", " "), partes[4].replace("_", " ")]
    return any(n and n in prod_l for n in nombres)


def _cve_afecta(cve_data: dict, producto: str, version: str) -> bool:
    for conf in cve_data.get("configurations", []):
        for nodo in conf.get("nodes", []):
            for cm in nodo.get("cpeMatch", []):
                if (
                    cm.get("vulnerable")
                    and _coincide_producto(producto, cm)
                    and version_afectada(version, cm)
                ):
                    return True
    return False


@dataclass
class CveEncontrado:
    cve_id: str
    descripcion: str
    cvss_score: Optional[float]
    severidad_nvd: Optional[str]


@dataclass
class ResultadoBusquedaCVE:
    estado: str  # verificado | nvd_no_disponible
    cves: list[CveEncontrado]
    error: Optional[str] = None


def buscar_cves_por_producto(
    producto: str, version: str, max_resultados: int = 5
) -> ResultadoBusquedaCVE:
    """
    CVEs de NVD que afectan a 'producto version' (confirmado contra el
    cpeMatch, no solo por mencion en el texto). Ordenados por CVSS.
    """
    if not producto.strip() or not version.strip():
        return ResultadoBusquedaCVE(estado=ESTADO_VERIFICADO, cves=[])

    data, error = _consultar_nvd(
        {"keywordSearch": producto.strip(), "resultsPerPage": 2000}
    )
    if data is None:
        return ResultadoBusquedaCVE(estado=ESTADO_NO_DISPONIBLE, cves=[], error=error)

    encontrados: list[CveEncontrado] = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        if _cve_afecta(cve_data, producto, version):
            score, sev = _extraer_cvss(cve_data)
            encontrados.append(
                CveEncontrado(cve_data.get("id", ""), _descripcion_en(cve_data), score, sev)
            )

    encontrados.sort(key=lambda c: c.cvss_score or 0.0, reverse=True)
    return ResultadoBusquedaCVE(estado=ESTADO_VERIFICADO, cves=encontrados[:max_resultados])
