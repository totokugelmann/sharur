"""
Sharur SAIC - app/services/analisis_ia_service.py

Orquestador del pipeline evidence-first completo:

  herramienta (tools_service, ya gateada)
      -> evidence blob
      -> LLM propone hallazgos (llm_service)
      -> por cada hallazgo propuesto:
           a) se valida que la cita exista en la evidencia cruda
              (llm_service.find_quote_source)
           b) si el hallazgo trae CVE, se verifica contra NVD
              (cve_search_service.verificar_cve_en_nvd)
           c) se asigna confianza:
                - CONFIRMADA: cita valida + CVE verificado en NVD
                - PROBABLE: cita valida, CVE no verificable o sin CVE
                - DESCARTADA: cita no encontrada en la evidencia
      -> todo hallazgo (incluidos los DESCARTADOS) se persiste y
         se audita, para que quede trazabilidad completa de que
         se le propuso al modelo y por que se acepto o rechazo.
"""

from typing import Optional

from sqlalchemy.orm import Session

from app.models.auditoria import TipoEvento
from app.models.notificacion import ConfianzaHallazgo, Hallazgo, SeveridadHallazgo
from app.services import auditoria_service, tools_service
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
    dispositivo_id: int,
    username: str,
    herramienta: str,
    resultado_tool,
) -> list[Hallazgo]:
    """
    Corre el pipeline evidence-first (LLM -> validacion de cita ->
    verificacion NVD -> persistencia) sobre un ToolResult YA
    OBTENIDO. Separado de `ejecutar_analisis_ia` para que un
    llamador que ya corrio la herramienta (por ejemplo el CLI, que
    deja al operador elegir objetivo/perfil de escaneo de forma
    interactiva) no tenga que volver a ejecutarla desde cero solo
    para analizarla.
    """
    if resultado_tool.status not in ("ok", "error"):
        # rechazado_gating, timeout, not_found: no tiene sentido mandarlo al LLM
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


def ejecutar_analisis_ia(
    db: Session,
    caso_id: int,
    dispositivo_id: int,
    username: str,
    herramienta: str,
    target: str,
) -> list[Hallazgo]:
    """
    Corre una herramienta gateada, pasa su salida al LLM, valida
    cada hallazgo propuesto contra la evidencia cruda y contra
    NVD, y persiste todos los resultados (confirmados, probables
    y descartados).

    Usado por la API HTTP, donde no existe un ToolResult previo.
    Si ya tenes uno (por ejemplo el CLI, tras dejar elegir objetivo/
    perfil al operador), usa `analizar_evidencia` directamente para
    no correr la herramienta dos veces.
    """
    if herramienta == "nmap":
        resultado_tool = tools_service.run_nmap(db, caso_id, dispositivo_id, username, target)
    elif herramienta == "httpx":
        resultado_tool = tools_service.run_httpx(db, caso_id, dispositivo_id, username, target)
    elif herramienta == "testssl":
        resultado_tool = tools_service.run_testssl(db, caso_id, dispositivo_id, username, target)
    elif herramienta == "nuclei":
        resultado_tool = tools_service.run_nuclei_deteccion(db, caso_id, dispositivo_id, username, target)
    else:
        raise ValueError(f"Herramienta '{herramienta}' no soportada por el pipeline de analisis IA.")

    return analizar_evidencia(db, caso_id, dispositivo_id, username, herramienta, resultado_tool)
