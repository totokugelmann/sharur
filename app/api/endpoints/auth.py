"""
Sharur SAIC - app/api/endpoints/auth.py

Login basico. En produccion esto deberia integrarse con el
directorio de usuarios de la SAIC (LDAP/AD u otro IdP
institucional) en vez de una tabla de usuarios propia; se deja
aca un flujo minimo de username/password + JWT para desarrollo y
pruebas.
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm

from app.core.security import create_access_token, verify_password

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

# Placeholder en memoria: reemplazar por consulta a la tabla de
# usuarios institucional / IdP antes de cualquier uso real.
#
# Solo existen dos roles de login (ver core/config.py):
# - admin: gestion de cuentas de operadores.
# - operador: control funcional total del sistema (unico rol que
#   opera el dia a dia de un caso).
#
# Usuarios y contraseñas de DESARROLLO (NUNCA usar en produccion):
#   admin      / admin123
#   operador1  / operador123
_USUARIOS_DEV = {
    "admin": {
        "hashed_password": "$2b$12$.KbVyKd4gH.CPAXstn9jKOmzM/q48rr0YrSTvVzpDSQIBaG4c8BMy",
        "role": "admin",
    },
    "operador1": {
        "hashed_password": "$2b$12$3bKh0oXaF1Y4MenbLUpv1uEahPbICzsaeZSn1HCZzCCcETFsuKHt2",
        "role": "operador",
    },
}


@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    usuario = _USUARIOS_DEV.get(form_data.username)
    if usuario is None or not verify_password(form_data.password, usuario["hashed_password"]):
        raise HTTPException(status_code=401, detail="Credenciales invalidas.")

    token = create_access_token(subject=form_data.username, role=usuario["role"])
    return {"access_token": token, "token_type": "bearer"}
