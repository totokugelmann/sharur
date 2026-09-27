"""
Sharur SAIC - app/core/security.py

Utilidades criptograficas para integridad de evidencia.

Alcance de este modulo:
- hashing/verificacion de integridad (SHA-256) de texto y de archivos.

NO decide alcance de intervencion (eso es gating_service).
NO maneja autenticacion (el MVP del CLI pide el operador por teclado
y lo firma en la cadena de auditoria; no hay login ni tokens).
"""

import hashlib


def sha256_of_text(text: str) -> str:
    """Hash SHA-256 de un string UTF-8. Usado para firmar entradas de auditoría."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_of_file(path: str, chunk_size: int = 65536) -> str:
    """Hash SHA-256 de un archivo, leído en bloques para no cargar todo en memoria."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
