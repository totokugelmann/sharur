"""
Sharur SAIC - app/services/analisis_ia_service.py
"""

import re
from typing import Optional
from sqlalchemy.orm import Session

from app.core.logging import logger
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

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

def _normalizar_severidad(valor: Optional[str]) -> SeveridadHallazgo:
    if not valor:
        return SeveridadHallazgo.INFORMATIVA
    return _MAPA_SEVERIDAD.get(valor.strip().lower(), SeveridadHallazgo.INFORMATIVA)

def limpiar_cves_no_verificados(texto: str, verificados: set[str]) -> str:
    return CVE_RE.sub(lambda m: m.group(0) if m.group(0) in verificados else "[CVE no verificado]", texto)


def analizar_evidencia(
    db: Session,
    caso_id: int,
    username: str,
    herramienta: str,
    resultado_tool,
    dispositivo_id: Optional[int] = None,
) -> list[Hallazgo]:
    
    if resultado_tool.status not in ("ok", "error"):
        return []

    texto_para_ia = resultado_tool.output

    if herramienta == "nmap":
        lineas_relevantes = []
        for linea in texto_para_ia.splitlines():
            if "open" in linea.lower() or "VERSION" in linea or "|_" in linea:
                # Filtro de ruido: evitamos que la IA se confunda con certificados o fechas
                if any(ruido in linea for ruido in ["ssl-cert", "Not valid", "ssl-date", "ssh-hostkey", "clock-skew"]):
                    continue
                lineas_relevantes.append(linea)
        
        if not lineas_relevantes:
            logger.info("Nmap no encontró puertos abiertos. Omitiendo análisis de IA.")
            return []
            
        texto_para_ia = "PUERTOS ABIERTOS:\n" + "\n".join(lineas_relevantes)

    evidence_blob = build_evidence_blob(herramienta, texto_para_ia)

    auditoria_service.registrar_evento(
        db, caso_id=caso_id, tipo_evento=TipoEvento.HALLAZGO_IA_PROPUESTO,
        descripcion=f"Evidencia de '{herramienta}' enviada al modelo para analisis.",
        actor_username=username, dispositivo_id=dispositivo_id,
        detalle={"herramienta": herramienta, "evidencia_hash": resultado_tool.evidence_hash},
    )

    propuestas, fue_truncado = proponer_hallazgos(evidence_blob)
    
    if fue_truncado:
        print(f"\n[!] ADVERTENCIA: El modelo generó demasiados datos y se cortó. Se recuperaron {len(propuestas)} hallazgos.")
        auditoria_service.registrar_evento(
            db, caso_id=caso_id, tipo_evento=TipoEvento.HALLAZGO_IA_PROPUESTO,
            descripcion=f"Respuesta del modelo truncada. Se recuperaron {len(propuestas)} hallazgos parciales.",
            actor_username=username, dispositivo_id=dispositivo_id,
            detalle={"recuperados": len(propuestas)},
        )

    hallazgos_persistidos: list[Hallazgo] = []

    for propuesta in propuestas:
        cita = propuesta.get("cita_evidencia", "")
        cve_id = propuesta.get("cve_id")
        titulo = propuesta.get("titulo", "Hallazgo sin titulo")
        descripcion = propuesta.get("descripcion", "")
        severidad_sugerida = _normalizar_severidad(propuesta.get("severidad_sugerida"))

        # Usa la nueva función tolerante de llm_service
        cita_valida = find_quote_source(cita, texto_para_ia)

        if not cita_valida:
            confianza = ConfianzaHallazgo.DESCARTADA
            nvd_verificado = False
            nvd_score = None
            severidad_final = severidad_sugerida
        else:
            nvd_verificado = False
            nvd_score = None
            severidad_final = severidad_sugerida
            
            if cve_id and is_cve(cve_id):
                verificacion = verificar_cve_en_nvd(cve_id)
                if verificacion.existe:
                    nvd_verificado = True
                    nvd_score = verificacion.cvss_score
                    confianza = ConfianzaHallazgo.CONFIRMADA
                    
                    if nvd_score is not None:
                        if nvd_score >= 9.0: severidad_final = SeveridadHallazgo.CRITICA
                        elif nvd_score >= 7.0: severidad_final = SeveridadHallazgo.ALTA
                        elif nvd_score >= 4.0: severidad_final = SeveridadHallazgo.MEDIA
                        else: severidad_final = SeveridadHallazgo.BAJA
                    
                    if verificacion.descripcion:
                        descripcion = f"{descripcion}\n\n[NVD] {verificacion.descripcion}"
                else:
                    confianza = ConfianzaHallazgo.PROBABLE
            else:
                confianza = ConfianzaHallazgo.PROBABLE

        if not nvd_verificado:
            descripcion = limpiar_cves_no_verificados(descripcion, set())

        hallazgo = Hallazgo(
            caso_id=caso_id,
            dispositivo_id=dispositivo_id, 
            herramienta_origen=herramienta,
            comando_ejecutado=" ".join(resultado_tool.command),
            cve_id=cve_id if (cve_id and is_cve(cve_id)) else None,
            titulo=titulo, descripcion=descripcion, cita_evidencia=cita,
            evidencia_cruda_hash=resultado_tool.evidence_hash,
            severidad=severidad_final, confianza=confianza,
            nvd_verificado=nvd_verificado, nvd_score=nvd_score,
        )
        db.add(hallazgo)
        db.flush()
        hallazgos_persistidos.append(hallazgo)

        tipo_evento_auditoria = (
            TipoEvento.HALLAZGO_VALIDADO if confianza != ConfianzaHallazgo.DESCARTADA else TipoEvento.HALLAZGO_DESCARTADO
        )

        auditoria_service.registrar_evento(
            db, caso_id=caso_id, tipo_evento=tipo_evento_auditoria,
            descripcion=f"Hallazgo '{titulo}' -> confianza={confianza.value}.",
            actor_username=username, dispositivo_id=dispositivo_id,
            detalle={
                "hallazgo_id": hallazgo.id, "cve_id": cve_id,
                "confianza": confianza.value, "nvd_verificado": nvd_verificado,
                "cita_evidencia": cita,
            },
        )

    return hallazgos_persistidos
