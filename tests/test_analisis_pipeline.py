"""Pipeline de analisis: via determinista (NVD) + via LLM, sin red ni base de datos."""

from types import SimpleNamespace

import pytest

from app.models.hallazgo import ConfianzaHallazgo
from app.services import analisis_ia_service as svc
from app.services.cve_search_service import (
    ESTADO_NO_DISPONIBLE, ESTADO_VERIFICADO, CveEncontrado, ResultadoBusquedaCVE,
)

NMAP = (
    "Nmap scan report for 10.0.0.5\n"
    "PORT   STATE SERVICE VERSION\n"
    "21/tcp open  ftp     vsftpd 2.3.4\n"
    "22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)\n"
)


@pytest.fixture
def entorno(monkeypatch):
    guardados = []

    def fake_registrar(db, **kw):
        h = SimpleNamespace(**{k: kw[k] for k in (
            "cve_id", "titulo", "cita", "confianza", "nvd_verificado", "severidad")})
        h.cita_evidencia = h.cita
        guardados.append(h)
        return h

    monkeypatch.setattr(svc, "_registrar_hallazgo", fake_registrar)
    monkeypatch.setattr(svc.auditoria_service, "registrar_evento", lambda *a, **k: None)
    tool = SimpleNamespace(status="ok", output=NMAP, command=["nmap"], evidence_hash="h")
    return guardados, tool


def test_cve_confirmado_sin_que_el_llm_lo_mencione(monkeypatch, entorno):
    guardados, tool = entorno
    monkeypatch.setattr(svc, "buscar_cves_por_producto", lambda p, v: ResultadoBusquedaCVE(
        ESTADO_VERIFICADO,
        [CveEncontrado("CVE-2011-2523", "backdoor", 9.8, "CRITICAL")] if p == "vsftpd" else []))
    monkeypatch.setattr(svc, "proponer_hallazgos", lambda blob: ([], False))

    res = svc.analizar_evidencia(None, 1, "op", "nmap", tool)
    assert len(res) == 1
    assert res[0].cve_id == "CVE-2011-2523"
    assert res[0].confianza == ConfianzaHallazgo.CONFIRMADA
    assert res[0].cita == "21/tcp open  ftp     vsftpd 2.3.4"


def test_cve_alucinado_por_el_llm_no_se_guarda_como_verificado(monkeypatch, entorno):
    guardados, tool = entorno
    monkeypatch.setattr(svc, "buscar_cves_por_producto", lambda p, v: ResultadoBusquedaCVE(ESTADO_VERIFICADO, []))
    monkeypatch.setattr(svc, "proponer_hallazgos", lambda blob: ([{
        "titulo": "x", "descripcion": "ver CVE-2099-9999", "severidad_sugerida": "alta",
        "cita_evidencia": "22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)",
        "cve_id": "CVE-2099-9999"}], False))
    monkeypatch.setattr(svc, "verificar_cve_en_nvd", lambda c: SimpleNamespace(
        existe=False, estado="no_existe", cvss_score=None, descripcion=""))

    res = svc.analizar_evidencia(None, 1, "op", "nmap", tool)
    assert res[0].confianza == ConfianzaHallazgo.PROBABLE and not res[0].nvd_verificado


def test_cita_inventada_se_descarta(monkeypatch, entorno):
    guardados, tool = entorno
    monkeypatch.setattr(svc, "buscar_cves_por_producto", lambda p, v: ResultadoBusquedaCVE(ESTADO_VERIFICADO, []))
    monkeypatch.setattr(svc, "proponer_hallazgos", lambda blob: ([{
        "titulo": "x", "descripcion": "d", "severidad_sugerida": "baja",
        "cita_evidencia": "3306/tcp open mysql MySQL 5.0.51a"}], False))
    assert svc.analizar_evidencia(None, 1, "op", "nmap", tool)[0].confianza == ConfianzaHallazgo.DESCARTADA


def test_nvd_caida_no_marca_nada_como_verificado(monkeypatch, entorno, capsys):
    guardados, tool = entorno
    monkeypatch.setattr(svc, "buscar_cves_por_producto",
                        lambda p, v: ResultadoBusquedaCVE(ESTADO_NO_DISPONIBLE, [], "503"))
    monkeypatch.setattr(svc, "proponer_hallazgos", lambda blob: ([], False))
    assert svc.analizar_evidencia(None, 1, "op", "nmap", tool) == []
    assert "NVD no respondio" in capsys.readouterr().out


def test_llm_caido_conserva_los_hallazgos_de_nvd(monkeypatch, entorno):
    guardados, tool = entorno
    monkeypatch.setattr(svc, "buscar_cves_por_producto", lambda p, v: ResultadoBusquedaCVE(
        ESTADO_VERIFICADO, [CveEncontrado("CVE-2011-2523", "d", 9.8, "CRITICAL")] if p == "vsftpd" else []))

    def caido(blob):
        raise ConnectionError("ollama off")

    monkeypatch.setattr(svc, "proponer_hallazgos", caido)
    assert len(svc.analizar_evidencia(None, 1, "op", "nmap", tool)) == 1


def test_inventario_de_dispositivos():
    arp = SimpleNamespace(output="10.0.0.1\t00:11:22:33:44:55\tTP-LINK TECHNOLOGIES\n10.0.0.9\taa:bb:cc:dd:ee:ff\t(Unknown)\n")
    nm = SimpleNamespace(output="Nmap scan report for 10.0.0.1\n80/tcp open http\n")
    inv = svc.identificar_dispositivos_red(None, 1, "op", arp, nm)
    assert inv[0]["ip"] == "10.0.0.1" and inv[0]["tipo"] == "Router / equipo de red"
    assert inv[1]["tipo"] == "Indeterminado"
