"""
Sharur SAIC - app/cli/sesion.py

Arranque de sesión del CLI. Todo por consola estándar (print/input).
Sin capa de UI.

Funciones:
  - crear_caso(db)          pide expediente, oficio y operador; crea el
                            caso y lo firma en la cadena de auditoría.
  - cerrar_caso(db, caso)   cierra el caso; no se puede volver a abrir.

Un caso se crea y se cierra dentro de la misma sesión del CLI.
"""

from sqlalchemy.orm import Session

from app.models.caso import Caso
from app.services import caso_service


def _prompt(mensaje: str, obligatorio: bool = True) -> str:
    """Lee una línea. Si obligatorio y viene vacío, vuelve a pedir."""
    while True:
        valor = input(f"{mensaje}: ").strip()
        if valor or not obligatorio:
            return valor
        print("[!] Este campo es obligatorio.")


def crear_caso(db: Session) -> Caso:
    """
    Pide los datos mínimos y crea el caso.
    La fecha de creación la pone el modelo (creado_en = utc_now).
    """
    print()
    print("=" * 50)
    print("  NUEVO CASO")
    print("=" * 50)

    numero_expediente = _prompt("Número de expediente")
    numero_oficio     = _prompt("Número de oficio")
    operador          = _prompt("Operador")

    datos = {
        "numero_causa": numero_expediente,
        "numero_oficio": numero_oficio,
        "caratula": "",
        "juzgado_interviniente": "",
        "fiscalia_interviniente": None,
        "descripcion": None,
    }

    caso = caso_service.crear_caso(db, datos, creado_por=operador)
    db.commit()
    db.refresh(caso)
    return caso


def cerrar_caso(db: Session, caso: Caso) -> None:
    """
    Cierra el caso. Una vez cerrado, no se puede volver a abrir
    (esa restricción vive en caso_service.cerrar_caso).
    """
    motivo = _prompt("Motivo de cierre", obligatorio=False) or "Cierre por fin de sesión"
    try:
        caso_service.cerrar_caso(
            db,
            caso,
            motivo_cierre=motivo,
            cerrado_por=caso.creado_por,
        )
        db.commit()
        print(f"[+] Caso #{caso.id} cerrado.")
    except ValueError as exc:
        print(f"[!] No se pudo cerrar el caso: {exc}")
