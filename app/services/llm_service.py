"""
Sharur SAIC - app/services/llm_service.py

Interfaz evidence-first con el modelo local (Ollama).

Adaptado de llm.py del Sharur original: el LLM propone, Python
valida. Se mantienen intactos los principios centrales:

- El system prompt prohibe expresamente inventar vulnerabilidades
  o proponer sin cita textual.
- normalize_whitespace() + find_quote_source() verifican que la
  cita exista literalmente (salvo espacios) en la evidencia cruda
  antes de aceptar cualquier hallazgo.
- Los hallazgos sin cita valida se descartan; los que tienen cita
  valida pero CVE no verificable en NVD se marcan PROBABLE en vez
  de CONFIRMADA (ver analisis_ia_service.py).
"""

import json
import re
from typing import Any, Dict, List, Optional

import requests

from app.core.config import get_settings
from app.core.logging import logger

settings = get_settings()

SYSTEM_PROMPT = """
Sos un motor de extraccion de evidencia estricto para auditoria de
seguridad autorizada judicialmente (SAIC).

Reglas absolutas:
1. NO sos un asistente creativo. NO podes adivinar.
2. NO podes inventar vulnerabilidades, CVEs, ni versiones de software.
3. Cada hallazgo que propongas DEBE incluir una cita textual EXACTA
   (copiada literalmente, sin parafrasear) tomada de la evidencia
   cruda que se te provee.
4. Si no encontras una cita textual que respalde un hallazgo, NO LO
   PROPONGAS.
5. Respondes UNICAMENTE en JSON valido, sin texto adicional, con esta
   forma exacta:

{
  "hallazgos": [
    {
      "titulo": "string",
      "cve_id": "CVE-YYYY-NNNNN o null si no aplica",
      "descripcion": "string",
      "cita_evidencia": "cita textual exacta de la evidencia",
      "severidad_sugerida": "critica|alta|media|baja|informativa"
    }
  ]
}

No agregues explicaciones fuera del JSON. No agregues markdown.
"""


def ask_ollama(evidence_blob: str) -> Optional[str]:
    payload = {
        "model": settings.OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": evidence_blob},
        ],
        "stream": False,
    }

    try:
        resp = requests.post(settings.OLLAMA_URL, json=payload, timeout=settings.OLLAMA_TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.error("Fallo consultando Ollama: %s", exc)
        return None

    data = resp.json()
    return data.get("message", {}).get("content")


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def extract_json_object(text: str) -> Dict[str, Any]:
    """
    Extrae el primer objeto JSON valido de la respuesta del modelo,
    tolerando que el modelo agregue texto extra pese a la
    instruccion del system prompt.
    """
    if not text:
        return {"hallazgos": []}

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return {"hallazgos": []}

    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        logger.warning("Respuesta del modelo no parseable como JSON.")
        return {"hallazgos": []}


def find_quote_source(quote: str, evidence_blob: str) -> bool:
    """
    Confirma que la cita propuesta por el modelo exista
    literalmente (normalizando espacios en blanco) dentro de la
    evidencia cruda real.
    """
    if not quote or not quote.strip():
        return False

    quote_normalizado = normalize_whitespace(quote)
    evidencia_normalizada = normalize_whitespace(evidence_blob)

    return quote_normalizado in evidencia_normalizada


def build_evidence_blob(tool_name: str, tool_output: str) -> str:
    return f"HERRAMIENTA: {tool_name}\nSALIDA:\n{tool_output}\n"


def proponer_hallazgos(evidence_blob: str) -> List[Dict[str, Any]]:
    """
    Llama al modelo y devuelve la lista cruda de hallazgos
    propuestos, SIN validar todavia. La validacion (cita +
    verificacion NVD) ocurre en analisis_ia_service.py.
    """
    respuesta_cruda = ask_ollama(evidence_blob)
    parsed = extract_json_object(respuesta_cruda or "")
    return parsed.get("hallazgos", [])
