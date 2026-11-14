"""Cliente NVD: estados, reintentos ante 5xx y filtrado por version (cpeMatch)."""

import pytest
import requests

from app.services import cve_search_service as nvd


class _Resp:
    def __init__(self, status=200, data=None):
        self.status_code, self._data = status, data or {}

    def json(self):
        return self._data


def _cve(cve_id, criteria, score=9.8, **rango):
    return {"cve": {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": f"desc {cve_id}"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": "CRITICAL"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": criteria, **rango}]}]}],
    }}


@pytest.fixture(autouse=True)
def _aislar(monkeypatch, tmp_path):
    monkeypatch.setattr(nvd, "_dormir", lambda s: None)
    monkeypatch.setattr(nvd, "_ultimo_request", 0.0)
    monkeypatch.setattr(nvd.settings, "NVD_CACHE_PATH", str(tmp_path / "cache.json"))


def test_version_exacta_y_rangos():
    exacta = {"criteria": "cpe:2.3:a:beasts:vsftpd:2.3.4:*:*:*:*:*:*:*"}
    assert nvd.version_afectada("2.3.4", exacta)
    assert not nvd.version_afectada("2.3.5", exacta)

    rango = {"criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "versionEndExcluding": "5.0"}
    assert nvd.version_afectada("4.7p1", rango)
    assert not nvd.version_afectada("5.0", rango)
    assert not nvd.version_afectada("7.2p2", rango)


def test_busqueda_filtra_por_version(monkeypatch):
    data = {"vulnerabilities": [
        _cve("CVE-2011-2523", "cpe:2.3:a:beasts:vsftpd:2.3.4:*:*:*:*:*:*:*", 9.8),
        _cve("CVE-2099-0001", "cpe:2.3:a:beasts:vsftpd:3.0.3:*:*:*:*:*:*:*", 9.0),
    ]}
    monkeypatch.setattr(nvd.requests, "get", lambda *a, **k: _Resp(200, data))
    r = nvd.buscar_cves_por_producto("vsftpd", "2.3.4")
    assert r.estado == nvd.ESTADO_VERIFICADO
    assert [c.cve_id for c in r.cves] == ["CVE-2011-2523"]


def test_busqueda_con_nvd_caida_no_dice_que_no_hay_cves(monkeypatch):
    llamadas = []

    def get(*a, **k):
        llamadas.append(1)
        return _Resp(503)

    monkeypatch.setattr(nvd.requests, "get", get)
    r = nvd.buscar_cves_por_producto("vsftpd", "2.3.4")
    assert r.estado == nvd.ESTADO_NO_DISPONIBLE
    assert len(llamadas) > 1  # reintento ante 5xx


def test_verificar_cve_tres_estados(monkeypatch):
    monkeypatch.setattr(nvd.requests, "get", lambda *a, **k: _Resp(200, {"vulnerabilities": [
        _cve("CVE-2011-2523", "cpe:2.3:a:beasts:vsftpd:2.3.4:*:*:*:*:*:*:*")]}))
    ok = nvd.verificar_cve_en_nvd("CVE-2011-2523")
    assert ok.existe and ok.estado == nvd.ESTADO_VERIFICADO and ok.cvss_score == 9.8

    monkeypatch.setattr(nvd.requests, "get", lambda *a, **k: _Resp(200, {"vulnerabilities": []}))
    assert nvd.verificar_cve_en_nvd("CVE-2000-0001").estado == nvd.ESTADO_NO_EXISTE

    def caido(*a, **k):
        raise requests.ConnectionError("sin red")

    monkeypatch.setattr(nvd.requests, "get", caido)
    assert nvd.verificar_cve_en_nvd("CVE-2000-0002").estado == nvd.ESTADO_NO_DISPONIBLE


def test_cache_evita_repetir_la_consulta(monkeypatch):
    n = []

    def get(*a, **k):
        n.append(1)
        return _Resp(200, {"vulnerabilities": []})

    monkeypatch.setattr(nvd.requests, "get", get)
    nvd.buscar_cves_por_producto("vsftpd", "2.3.4")
    nvd.buscar_cves_por_producto("vsftpd", "2.3.4")
    assert len(n) == 1
