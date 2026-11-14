"""Nivel de riesgo global: determinista, tope MEDIO para hallazgos no verificados."""

from types import SimpleNamespace

from app.models.hallazgo import ConfianzaHallazgo, SeveridadHallazgo
from app.services.riesgo_service import NivelRiesgo, nivel_riesgo_global


def _h(sev, conf):
    return SimpleNamespace(severidad=sev, confianza=conf)


def test_sin_hallazgos():
    assert nivel_riesgo_global([]) == NivelRiesgo.SIN_HALLAZGOS


def test_descartados_no_cuentan():
    hs = [_h(SeveridadHallazgo.CRITICA, ConfianzaHallazgo.DESCARTADA)]
    assert nivel_riesgo_global(hs) == NivelRiesgo.SIN_HALLAZGOS


def test_confirmado_critico_da_critico():
    hs = [_h(SeveridadHallazgo.CRITICA, ConfianzaHallazgo.CONFIRMADA)]
    assert nivel_riesgo_global(hs) == NivelRiesgo.CRITICO


def test_probable_critico_queda_topeado_en_medio():
    hs = [_h(SeveridadHallazgo.CRITICA, ConfianzaHallazgo.PROBABLE)]
    assert nivel_riesgo_global(hs) == NivelRiesgo.MEDIO


def test_toma_el_maximo():
    hs = [
        _h(SeveridadHallazgo.BAJA, ConfianzaHallazgo.CONFIRMADA),
        _h(SeveridadHallazgo.ALTA, ConfianzaHallazgo.CONFIRMADA),
        _h(SeveridadHallazgo.CRITICA, ConfianzaHallazgo.PROBABLE),
    ]
    assert nivel_riesgo_global(hs) == NivelRiesgo.ALTO
