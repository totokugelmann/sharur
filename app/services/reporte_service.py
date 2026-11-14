"""
Sharur SAIC - app/services/reporte_service.py

Exporta el informe de un caso a HTML (y a PDF si hay un motor disponible).

El informe reune: datos del caso, nivel de riesgo global, la tabla de
hallazgos y la cadena de auditoria completa (con sus hashes). Al final se
calcula el SHA-256 del archivo generado y se registra en la auditoria, de
modo que el propio informe queda encadenado como evidencia.

El PDF es opcional: si no hay motor (weasyprint), se entrega el HTML y se
avisa. No se agrega ninguna dependencia obligatoria nueva.
"""

import html
import os
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.core.security import sha256_of_file
from app.core.utils import utc_now
from app.models.auditoria import EventoAuditoria, TipoEvento
from app.models.caso import Caso
from app.models.hallazgo import ConfianzaHallazgo, Hallazgo
from app.services import auditoria_service
from app.services.riesgo_service import nivel_riesgo_global

try:
    from app.core.config import get_settings
    _REPORTS_DIR = get_settings().REPORTS_DIR
except Exception:  # pragma: no cover - fallback defensivo
    _REPORTS_DIR = "./reports"


def _e(valor) -> str:
    return html.escape(str(valor if valor is not None else "-"))


def _tabla_hallazgos(hallazgos: list[Hallazgo]) -> str:
    if not hallazgos:
        return "<p>No se registraron hallazgos.</p>"
    filas = []
    for h in hallazgos:
        nvd = f"CVSS {h.nvd_score}" if h.nvd_verificado and h.nvd_score is not None else "-"
        filas.append(
            "<tr>"
            f"<td>{_e(h.confianza.value)}</td>"
            f"<td>{_e(h.severidad.value)}</td>"
            f"<td>{_e(h.cve_id)}</td>"
            f"<td>{_e(nvd)}</td>"
            f"<td>{_e(h.titulo)}</td>"
            f"<td><code>{_e(h.cita_evidencia)}</code></td>"
            "</tr>"
        )
    return (
        "<table><thead><tr>"
        "<th>Confianza</th><th>Severidad</th><th>CVE</th><th>NVD</th>"
        "<th>Título</th><th>Cita de evidencia</th>"
        "</tr></thead><tbody>" + "".join(filas) + "</tbody></table>"
    )


def _tabla_auditoria(eventos: list[EventoAuditoria]) -> str:
    filas = []
    for e in eventos:
        filas.append(
            "<tr>"
            f"<td>{e.secuencia:04d}</td>"
            f"<td>{_e(e.tipo_evento.value)}</td>"
            f"<td>{_e(e.actor_username)}</td>"
            f"<td>{_e(e.descripcion)}</td>"
            f"<td><code>{_e(e.hash_evento[:16])}…</code></td>"
            "</tr>"
        )
    return (
        "<table><thead><tr>"
        "<th>#</th><th>Evento</th><th>Actor</th><th>Descripción</th><th>Hash</th>"
        "</tr></thead><tbody>" + "".join(filas) + "</tbody></table>"
    )


def construir_html(db: Session, caso: Caso) -> str:
    hallazgos = (
        db.query(Hallazgo)
        .filter(Hallazgo.caso_id == caso.id)
        .order_by(Hallazgo.severidad.desc(), Hallazgo.id.asc())
        .all()
    )
    eventos = (
        db.query(EventoAuditoria)
        .filter(EventoAuditoria.caso_id == caso.id)
        .order_by(EventoAuditoria.secuencia.asc())
        .all()
    )
    verif = auditoria_service.verificar_cadena(db, caso.id)
    nivel = nivel_riesgo_global(hallazgos)
    confirmados = sum(1 for h in hallazgos if h.confianza == ConfianzaHallazgo.CONFIRMADA)

    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>Informe de caso {_e(caso.numero_causa)}</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #111; }}
 h1, h2 {{ border-bottom: 1px solid #ccc; padding-bottom: .3rem; }}
 table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: .9rem; }}
 th, td {{ border: 1px solid #ccc; padding: .4rem .5rem; text-align: left; vertical-align: top; }}
 th {{ background: #f3f3f3; }}
 code {{ font-size: .8rem; word-break: break-all; }}
 .riesgo {{ display: inline-block; padding: .3rem .8rem; border-radius: .3rem; font-weight: bold; }}
 .critico {{ background:#b00020; color:#fff; }} .alto {{ background:#e65100; color:#fff; }}
 .medio {{ background:#f9a825; }} .bajo {{ background:#2e7d32; color:#fff; }}
 .sin_hallazgos {{ background:#607d8b; color:#fff; }}
 .meta td:first-child {{ width: 14rem; font-weight: bold; background:#fafafa; }}
 .integra {{ color:#2e7d32; }} .rota {{ color:#b00020; font-weight:bold; }}
</style></head><body>
<h1>Informe de caso — {_e(caso.numero_causa)}</h1>
<table class="meta">
 <tr><td>Expediente</td><td>{_e(caso.numero_causa)}</td></tr>
 <tr><td>Oficio</td><td>{_e(caso.numero_oficio)}</td></tr>
 <tr><td>Operador</td><td>{_e(caso.creado_por)}</td></tr>
 <tr><td>Estado</td><td>{_e(caso.estado.value)}</td></tr>
 <tr><td>Creado</td><td>{_e(caso.creado_en)}</td></tr>
 <tr><td>Cerrado</td><td>{_e(caso.cerrado_en)}</td></tr>
 <tr><td>Hash reporte final</td><td><code>{_e(caso.hash_reporte_final)}</code></td></tr>
 <tr><td>Informe generado</td><td>{_e(utc_now().isoformat())}</td></tr>
</table>

<h2>Nivel de riesgo global</h2>
<p><span class="riesgo {nivel.value}">{_e(nivel.value.upper())}</span>
   &nbsp; {confirmados} hallazgo(s) confirmado(s) sobre {len(hallazgos)} registrado(s).</p>

<h2>Hallazgos</h2>
{_tabla_hallazgos(hallazgos)}

<h2>Cadena de auditoría ({verif['total_eventos']} eventos)</h2>
<p>Integridad:
 <span class="{'integra' if verif['integra'] else 'rota'}">{_e(verif['detalle'])}</span></p>
{_tabla_auditoria(eventos)}
</body></html>"""


def exportar_informe(
    db: Session, caso: Caso, formato: str = "html", registrar: Optional[bool] = None
) -> dict:
    """
    Genera el informe del caso. Devuelve {'ruta', 'formato', 'hash_sha256'}.
    'formato' puede ser 'html' o 'pdf' (pdf cae a html si no hay motor).

    'registrar' controla si la exportacion deja un evento en la auditoria.
    Por defecto (None) solo se registra cuando el caso esta ABIERTO: un caso
    cerrado es inmutable, asi que exportarlo NO altera su cadena de auditoria
    ni su hash_reporte_final.
    """
    from app.models.caso import EstadoCaso

    if registrar is None:
        registrar = caso.estado == EstadoCaso.ABIERTO
    os.makedirs(_REPORTS_DIR, exist_ok=True)
    contenido = construir_html(db, caso)
    marca = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"informe_caso_{caso.id}_{marca}"

    ruta_html = os.path.join(_REPORTS_DIR, base + ".html")
    with open(ruta_html, "w", encoding="utf-8") as fh:
        fh.write(contenido)

    ruta_final = ruta_html
    formato_final = "html"
    if formato == "pdf":
        ruta_pdf = os.path.join(_REPORTS_DIR, base + ".pdf")
        try:
            from weasyprint import HTML  # import tardio: dependencia opcional
            HTML(string=contenido).write_pdf(ruta_pdf)
            ruta_final, formato_final = ruta_pdf, "pdf"
        except Exception:
            # Sin motor de PDF: se entrega el HTML (que puede imprimirse a PDF).
            pass

    hash_archivo = sha256_of_file(ruta_final)

    if registrar:
        auditoria_service.registrar_evento(
            db, caso_id=caso.id, tipo_evento=TipoEvento.INFORME_EXPORTADO,
            descripcion=f"Informe exportado ({formato_final}).",
            actor_username=caso.creado_por,
            detalle={"archivo": os.path.basename(ruta_final), "hash_sha256": hash_archivo},
        )

    return {"ruta": ruta_final, "formato": formato_final, "hash_sha256": hash_archivo}
