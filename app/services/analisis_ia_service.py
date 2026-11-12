"""
Sharur SAIC - app/services/analisis_ia_service.py

Orquestador del pipeline evidence-first completo.
Adaptado para funcionar a nivel de Caso (sin dispositivo_id obligatorio).
"""

from typing import Optional
from sqlalchemy.orm import Session

from app.models.auditoria import TipoEvento
from app.models.hallazgo import ConfianzaHallazgo, Hallazgo, SeveridadHallazgo
from app.services import auditoria_service
from app.services.cve_search_service import is_cve, verificar_cve_en_nvd
from app.services.llm_service import build_evidence_blob, find_quote_source, proponer_hallazgos

_MAPA_SEVERIDAD = {
    "critica": SeveridadHallazgo.CRITICA,
    "alta": SeveridadHallazgo.ALTA,
    "media": SeveridadHallazgo.MEDIA,
    "baja": SeveridadHallazgo.BAJA,
    "informativa": SeveridadHallazgo.INFORMATIVA,
}

def _normalizar_severidad(valor: Optional[str]) -> SeveridadHallazgo:
    if not valor:
        return SeveridadHallazgo.INFORMATIVA
    return _MAPA_SEVERIDAD.get(valor.strip().lower(), SeveridadHallazgo.INFORMATIVA)


def analizar_evidencia(
    db: Session,
    caso_id: int,
    username: str,
    herramienta: str,
    resultado_tool,
    dispositivo_id: Optional[int] = None,
) -> list[Hallazgo]:
    """
    Corre el pipeline evidence-first sobre un ToolResult YA OBTENIDO.
    """
    if resultado_tool.status not in ("ok", "error"):
        return []

    evidence_blob = build_evidence_blob(herramienta, resultado_tool.output)

    auditoria_service.registrar_evento(
        db,
        caso_id=caso_id,
        tipo_evento=TipoEvento.HALLAZGO_IA_PROPUESTO,
        descripcion=f"Evidencia de '{herramienta}' enviada al modelo para analisis.",
        actor_username=username,
        dispositivo_id=dispositivo_id,
        detalle={"herramienta": herramienta, "evidencia_hash": resultado_tool.evidence_hash},
    )

    # Llamamos al LLM
    propuestas = proponer_hallazgos(evidence_blob)
    hallazgos_persistidos: list[Hallazgo] = []

    for propuesta in propuestas:
        cita = propuesta.get("cita_evidencia", "")
        cve_id = propuesta.get("cve_id")
        titulo = propuesta.get("titulo", "Hallazgo sin titulo")
        descripcion = propuesta.get("descripcion", "")
        severidad_sugerida = _normalizar_severidad(propuesta.get("severidad_sugerida"))

        cita_valida = find_quote_source(cita, resultado_tool.output)

        if not cita_valida:
            confianza = ConfianzaHallazgo.DESCARTADA
            nvd_verificado = False
            nvd_score = None
            severidad_final = severidad_sugerida
        else:
            nvd_verificado = False
            nvd_score = None
            if cve_id and is_cve(cve_id):
                verificacion = verificar_cve_en_nvd(cve_id)
                if verificacion.existe:
                    nvd_verificado = True
                    nvd_score = verificacion.cvss_score
                    confianza = ConfianzaHallazgo.CONFIRMADA
                    if verificacion.descripcion:
                        descripcion = f"{descripcion}\n\n[NVD] {verificacion.descripcion}"
                else:
                    confianza = ConfianzaHallazgo.PROBABLE
            else:
                confianza = ConfianzaHallazgo.PROBABLE

            severidad_final = severidad_sugerida

        hallazgo = Hallazgo(
            dispositivo_id=dispositivo_id,
            herramienta_origen=herramienta,
            comando_ejecutado=" ".join(resultado_tool.command),
            cve_id=cve_id if (cve_id and is_cve(cve_id)) else None,
            titulo=titulo,
            descripcion=descripcion,
            cita_evidencia=cita,
            evidencia_cruda_hash=resultado_tool.evidence_hash,
            severidad=severidad_final,
            confianza=confianza,
            nvd_verificado=nvd_verificado,
            nvd_score=nvd_score,
        )
        db.add(hallazgo)
        db.flush()
        hallazgos_persistidos.append(hallazgo)

        tipo_evento_auditoria = (
            TipoEvento.HALLAZGO_VALIDADO
            if confianza != ConfianzaHallazgo.DESCARTADA
            else TipoEvento.HALLAZGO_DESCARTADO
        )

        auditoria_service.registrar_evento(
            db,
            caso_id=caso_id,
            tipo_evento=tipo_evento_auditoria,
            descripcion=f"Hallazgo '{titulo}' -> confianza={confianza.value}.",
            actor_username=username,
            dispositivo_id=dispositivo_id,
            detalle={
                "hallazgo_id": hallazgo.id,
                "cve_id": cve_id,
                "confianza": confianza.value,
                "nvd_verificado": nvd_verificado,
                "cita_evidencia": cita,
            },
        )

    return hallazgos_persistidos
