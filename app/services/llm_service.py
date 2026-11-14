"""
Sharur SAIC - app/services/llm_service.py
"""

import json
import re
from typing import Any, Dict, List, Optional
import requests

from app.core.config import get_settings
from app.core.logging import logger

settings = get_settings()

SYSTEM_PROMPT = """
Sos un analista forense de ciberseguridad.
Tu tarea es leer la evidencia de Nmap y proponer hallazgos (exposiciones o problemas de configuracion).
REGLA 1: Solo podes proponer un hallazgo si copias textualmente una cita de la evidencia (una linea de puerto, o esa linea mas las lineas '|' que le siguen).
REGLA 2: Se conciso. Cada descripcion debe tener MAXIMO 25 PALABRAS.
REGLA 3: NO inventes ni recuerdes CVEs. Completa "cve_id" solo si el identificador aparece escrito en la evidencia. El sistema busca los CVEs por producto y version en la NVD por su cuenta.
REGLA 4: Copia la cita exactamente como aparece. No inventes prefijos como "|_" si no estan en la linea original.
"""


def ask_ollama(evidence_blob: str) -> Optional[Dict[str, Any]]:
    schema = {
        "type": "object",
        "properties": {
            "hallazgos": {
                "type": "array",
                "maxItems": 30, # Aumentado para que entren todos los puertos de Metasploitable
                "items": {
                    "type": "object",
                    "properties": {
                        "titulo": {"type": "string"},
                        "cve_id": {"type": "string"},
                        "descripcion": {"type": "string"},
                        "cita_evidencia": {"type": "string"},
                        "severidad_sugerida": {
                            "type": "string", 
                            "enum": ["critica", "alta", "media", "baja", "informativa"]
                        }
                    },
                    "required": ["titulo", "descripcion", "cita_evidencia", "severidad_sugerida"]
                }
            }
        },
        "required": ["hallazgos"]
    }

    payload = {
        "model": settings.OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": evidence_blob},
        ],
        "stream": False,
        "think": False,
        "format": schema,
        "options": {
            "num_ctx": 8192,
            "num_predict": 4000, # Margen extra por si el JSON es muy largo
            "temperature": 0.1
        }
    }

    try:
        resp = requests.post(settings.OLLAMA_URL, json=payload, timeout=settings.OLLAMA_TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.error("Fallo consultando Ollama: %s", exc)
        raise ConnectionError(f"El modelo local falló o no respondió en {settings.OLLAMA_TIMEOUT}s: {exc}")

    data = resp.json()
    
    # LOGS DE DIAGNÓSTICO
    logger.warning(
        "OLLAMA METRICS -> done_reason=%s | eval_count=%s | prompt_eval_count=%s",
        data.get("done_reason"), data.get("eval_count"), data.get("prompt_eval_count")
    )
    
    return data


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def rescatar_hallazgos(texto: str) -> tuple[List[Dict[str, Any]], bool]:
    if not texto:
        return [], False

    texto = re.sub(r"<think>.*?</think>", "", texto, flags=re.DOTALL)
    texto = re.sub(r"```(?:json)?(.*?)```", r"\1", texto, flags=re.DOTALL)

    try:
        data = json.loads(texto)
        return data.get("hallazgos", []), False
    except json.JSONDecodeError:
        pass

    clave = texto.find('"hallazgos"')
    ini = texto.find("[", clave) if clave != -1 else -1
    if ini == -1:
        return [], True

    dec = json.JSONDecoder()
    pos = ini + 1
    items = []
    sep = re.compile(r"\s*,?\s*")
    
    while True:
        pos = sep.match(texto, pos).end()
        if pos >= len(texto) or texto[pos] != "{":
            break
        try:
            obj, pos = dec.raw_decode(texto, pos)
        except json.JSONDecodeError:
            break
        items.append(obj)
        
    return items, True


def _norm_linea(s: str) -> str:
    # Quita prefijos como |_ , | , espacios, y pasa a minusculas
    s = re.sub(r"^[\s|_]+", "", s)
    return re.sub(r"\s+", " ", s).strip().lower()


def find_quote_source(quote: str, evidence_blob: str) -> bool:
    """
    ¿La cita existe textualmente en la evidencia? Tolera prefijos '|_',
    mayusculas, espacios y citas de VARIAS lineas consecutivas (los bloques
    de puerto de nmap ocupan varias lineas).
    """
    if not quote or not quote.strip():
        return False

    lineas_cita = [
        _norm_linea(l.strip().strip('"').rstrip("."))
        for l in quote.splitlines() if l.strip()
    ]
    c = " ".join(l for l in lineas_cita if l)

    # Si la cita es muy corta, no la consideramos valida (evita falsos positivos)
    if len(c) < 12:
        return False

    evidencia = " ".join(_norm_linea(l) for l in evidence_blob.splitlines() if l.strip())
    return c in evidencia


def build_evidence_blob(tool_name: str, tool_output: str) -> str:
    return f"HERRAMIENTA: {tool_name}\nSALIDA:\n{tool_output}\n"


def proponer_hallazgos(evidence_blob: str) -> tuple[List[Dict[str, Any]], bool]:
    data = ask_ollama(evidence_blob)
    if not data:
        return [], False
        
    respuesta_cruda = data.get("message", {}).get("content", "")
    return rescatar_hallazgos(respuesta_cruda)
