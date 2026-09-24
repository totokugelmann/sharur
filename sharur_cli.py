#!/usr/bin/env python3
"""
Sharur SAIC - sharur_cli.py

Punto de entrada del CLI. Todo el flujo es por consola estándar
(input/print). No hay capa de UI.

Flujo:
  1. Menú principal
       [1] Crear caso
       [2] Salir
  2. Creación de caso: número de expediente, número de oficio, operador.
     La fecha se registra automáticamente y el alta queda firmada en la
     cadena de auditoría.
  3. Al crear el caso se entra al menú de análisis. Al salir de ese menú,
     el caso se cierra. Un caso cerrado no se puede volver a abrir.

Uso:
    python sharur_cli.py
"""

import sys

import app.models  # noqa: F401 — registra todos los modelos SQLAlchemy
from app.cli import sesion
from app.cli.menu_analisis import menu_analisis
from app.models.base import Base, SessionLocal, engine

# Crea las tablas faltantes al arrancar.
# MVP: sin Alembic. Reemplazar por migraciones formales en producción.
Base.metadata.create_all(bind=engine)


def menu_principal(db) -> bool:
    """Devuelve False para salir, True para repetir el menú."""
    print()
    print("=" * 50)
    print("  SHARUR SAIC")
    print("=" * 50)
    print("  [1] Crear caso")
    print("  [2] Salir")
    print()

    eleccion = input("Opción: ").strip()

    if eleccion == "1":
        caso = sesion.crear_caso(db)
        if caso is None:
            print("[!] No se creó el caso.")
            return True

        print(f"\n[+] Caso creado — expediente {caso.numero_causa}")
        menu_analisis(db, caso)
        sesion.cerrar_caso(db, caso)
        return True

    if eleccion == "2":
        return False

    print("[!] Opción no válida.")
    return True


def main() -> None:
    db = SessionLocal()
    try:
        while menu_principal(db):
            pass
        print("\nSesión finalizada.")
    except KeyboardInterrupt:
        print("\n[!] Sesión interrumpida por el operador.")
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
