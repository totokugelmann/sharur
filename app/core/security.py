"""
Sharur SAIC - app/core/security.py

Autenticacion, autorizacion y utilidades criptograficas.

Este modulo NO decide el alcance de una intervencion (eso es
responsabilidad de gating_service). Aca solo se resuelve:
- quien es el usuario (autenticacion)
- que rol tiene (autorizacion generica de la API)
- hashing de passwords
- hashing/verificacion de integridad de evidencia

Nota de dependencia: se usa la libreria `bcrypt` directamente en
vez de `passlib`. `passlib` no tiene una release desde 2020 y su
capa de deteccion de version es incompatible con `bcrypt>=4.1`
(el atributo `bcrypt.__about__` que passlib espera leer fue
eliminado), lo que rompe el hashing de passwords con cualquier
instalacion moderna de `bcrypt`. Usar `bcrypt` directo evita esta
clase entera de problemas de compatibilidad.
"""

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from app.core.config import get_settings

settings = get_settings()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# bcrypt trunca (y en versiones nuevas, directamente rechaza) el
# input a partir del byte 72. Se corta explicitamente antes para
# evitar errores/silencios inconsistentes entre versiones.
_BCRYPT_MAX_BYTES = 72


# ─────────────────────────────────────────────
# PASSWORDS
# ─────────────────────────────────────────────

def hash_password(password: str) -> str:
    password_bytes = password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    password_bytes = plain_password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    try:
        return bcrypt.checkpw(password_bytes, hashed_password.encode("utf-8"))
    except (ValueError, TypeError):
        # Hash malformado o vacio: nunca autenticar, nunca romper el flujo.
        return False


# ─────────────────────────────────────────────
# JWT
# ─────────────────────────────────────────────

def create_access_token(subject: str, role: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode = {"sub": subject, "role": role, "exp": expire}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales invalidas o token expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    payload = decode_access_token(token)
    username = payload.get("sub")
    role = payload.get("role")
    if username is None or role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalido",
        )
    return {"username": username, "role": role}


def require_role(*allowed_roles: str):
    """
    Dependency factory de FastAPI: uso require_role(settings.ROLE_OPERADOR)
    en cualquier endpoint que requiera un rol especifico.
    """

    async def role_checker(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Rol '{user['role']}' no autorizado para esta operacion",
            )
        return user

    return role_checker


# ─────────────────────────────────────────────
# INTEGRIDAD DE EVIDENCIA (hashing)
# ─────────────────────────────────────────────

def sha256_of_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_of_file(path: str, chunk_size: int = 65536) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
