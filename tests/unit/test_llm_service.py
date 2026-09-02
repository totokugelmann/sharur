"""
Sharur SAIC - tests/unit/test_llm_service.py

Tests de la validacion evidence-first: una cita propuesta por el
modelo solo se acepta si existe literalmente (normalizando
espacios) en la evidencia cruda.
"""

from app.services.llm_service import extract_json_object, find_quote_source, normalize_whitespace


def test_normalize_whitespace_colapsa_espacios():
    assert normalize_whitespace("  hola   mundo\n\tchau  ") == "hola mundo chau"


def test_find_quote_source_encuentra_cita_exacta():
    evidencia = "PORT 22/tcp open ssh OpenSSH 7.4 (protocol 2.0)"
    cita = "OpenSSH 7.4 (protocol 2.0)"
    assert find_quote_source(cita, evidencia) is True


def test_find_quote_source_tolera_diferencias_de_espaciado():
    evidencia = "PORT 22/tcp   open    ssh    OpenSSH 7.4"
    cita = "open ssh OpenSSH 7.4"
    assert find_quote_source(cita, evidencia) is True


def test_find_quote_source_rechaza_cita_inventada():
    evidencia = "PORT 22/tcp open ssh OpenSSH 7.4"
    cita = "PORT 22/tcp open ssh OpenSSH 9.9 (version inventada)"
    assert find_quote_source(cita, evidencia) is False


def test_find_quote_source_rechaza_cita_vacia():
    assert find_quote_source("", "algo de evidencia") is False
    assert find_quote_source("   ", "algo de evidencia") is False


def test_extract_json_object_parsea_json_valido():
    texto = '{"hallazgos": [{"titulo": "x"}]}'
    resultado = extract_json_object(texto)
    assert resultado["hallazgos"][0]["titulo"] == "x"


def test_extract_json_object_tolera_texto_extra_alrededor():
    texto = 'Aca esta el resultado:\n{"hallazgos": []}\nFin.'
    resultado = extract_json_object(texto)
    assert resultado["hallazgos"] == []


def test_extract_json_object_devuelve_vacio_si_no_hay_json():
    resultado = extract_json_object("esto no es json para nada")
    assert resultado == {"hallazgos": []}
