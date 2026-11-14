"""Exportacion del informe: genera HTML con riesgo y cadena, y lo audita con su hash."""

from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401
from app.models.base import Base
from app.models.hallazgo import ConfianzaHallazgo, Hallazgo, SeveridadHallazgo
from app.services import caso_service, reporte_service


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(reporte_service, "_REPORTS_DIR", str(tmp_path))
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    yield s
    s.close()


def _caso(db):
    c = caso_service.crear_caso(db, {
        "numero_causa": "EXP-9", "numero_oficio": "OF-9", "caratula": "",
        "juzgado_interviniente": "", "fiscalia_interviniente": None, "descripcion": None,
    }, creado_por="op")
    db.commit()
    return c


def test_exporta_html_con_hash_y_lo_audita(db):
    caso = _caso(db)
    db.add(Hallazgo(
        caso_id=caso.id, herramienta_origen="nmap", comando_ejecutado="nmap",
        cve_id="CVE-2011-2523", titulo="vsftpd backdoor", descripcion="d",
        cita_evidencia="21/tcp open ftp vsftpd 2.3.4", evidencia_cruda_hash="x",
        severidad=SeveridadHallazgo.CRITICA, confianza=ConfianzaHallazgo.CONFIRMADA,
        nvd_verificado=True, nvd_score=9.8,
    ))
    db.commit()

    res = reporte_service.exportar_informe(db, caso, formato="html")
    db.commit()

    assert res["formato"] == "html"
    assert len(res["hash_sha256"]) == 64
    html = open(res["ruta"], encoding="utf-8").read()
    assert "CRITICO" in html and "CVE-2011-2523" in html

    from app.models.auditoria import EventoAuditoria, TipoEvento
    ev = db.query(EventoAuditoria).filter(
        EventoAuditoria.tipo_evento == TipoEvento.INFORME_EXPORTADO).one()
    assert res["hash_sha256"] in ev.detalle_json


def test_pdf_cae_a_html_si_no_hay_motor(db):
    caso = _caso(db)
    res = reporte_service.exportar_informe(db, caso, formato="pdf")
    db.commit()
    assert res["formato"] in ("pdf", "html")  # html si weasyprint no esta instalado
