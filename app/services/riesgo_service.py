"""
Sharur SAIC - app/services/riesgo_service.py

Nivel de riesgo global de un caso, calculado de forma determinista a partir
de los hallazgos guardados (no lo decide el LLM).

Regla:
  - Se toma la severidad mas alta entre los hallazgos CONFIRMADOS (NVD).
  - Los hallazgos PROBABLES (sin verificar) pueden elevar el nivel como
    maximo a MEDIO.
  - Los DESCARTADOS no cuentan.
  - Sin hallazgos que cuenten -> SIN_HALLAZGOS.
"""

import enum
from typing import Iterable

from app.models.hallazgo import ConfianzaHallazgo, SeveridadHallazgo


class NivelRiesgo(str, enum.Enum):
    SIN_HALLAZGOS = "sin_hallazgos"
    BAJO = "bajo"
    MEDIO = "medio"
    ALTO = "alto"
    CRITICO = "critico"


_ORDEN = [
    NivelRiesgo.SIN_HALLAZGOS,
    NivelRiesgo.BAJO,
    NivelRiesgo.MEDIO,
    NivelRiesgo.ALTO,
    NivelRiesgo.CRITICO,
]

_DESDE_SEVERIDAD = {
    SeveridadHallazgo.INFORMATIVA: NivelRiesgo.BAJO,
    SeveridadHallazgo.BAJA: NivelRiesgo.BAJO,
    SeveridadHallazgo.MEDIA: NivelRiesgo.MEDIO,
    SeveridadHallazgo.ALTA: NivelRiesgo.ALTO,
    SeveridadHallazgo.CRITICA: NivelRiesgo.CRITICO,
}

TOPE_PROBABLES = NivelRiesgo.MEDIO


def _max(a: NivelRiesgo, b: NivelRiesgo) -> NivelRiesgo:
    return a if _ORDEN.index(a) >= _ORDEN.index(b) else b


def nivel_riesgo_global(hallazgos: Iterable) -> NivelRiesgo:
    nivel = NivelRiesgo.SIN_HALLAZGOS
    for h in hallazgos:
        if h.confianza == ConfianzaHallazgo.DESCARTADA:
            continue
        candidato = _DESDE_SEVERIDAD.get(h.severidad, NivelRiesgo.BAJO)
        if h.confianza == ConfianzaHallazgo.PROBABLE and _ORDEN.index(candidato) > _ORDEN.index(TOPE_PROBABLES):
            candidato = TOPE_PROBABLES
        nivel = _max(nivel, candidato)
    return nivel
