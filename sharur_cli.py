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
from app.cli import sesion, ui
from app.cli.menu_analisis import menu_analisis
from app.core.config import get_settings
from app.models.base import Base, SessionLocal, engine

# Crea las tablas faltantes al arrancar.
# MVP: sin Alembic. Reemplazar por migraciones formales en producción.
Base.metadata.create_all(bind=engine)

_settings = get_settings()


def menu_principal(db) -> bool:
    """Devuelve False para salir, True para repetir el menú."""
    eleccion = ui.menu(
        "SHARUR SAIC",
        [
            ("1", "Crear caso", "Alta de causa y apertura de la cadena de auditoría"),
            ("2", "Salir", "Cerrar Sharur"),
        ],
        subtitulo="Menú principal",
    )

    if eleccion == "1":
        caso = sesion.crear_caso(db)
        if caso is None:
            ui.advertencia("No se creó el caso.")
            return True

        ui.exito(f"Caso creado — expediente {caso.numero_causa}")
        menu_analisis(db, caso)
        sesion.cerrar_caso(db, caso)
        return True

    if eleccion == "2":
        return False

    ui.advertencia("Opción no válida.")
    return True


def main() -> None:
    ui.banner(version=f"v{_settings.APP_VERSION} · {_settings.APP_ENV}")
    db = SessionLocal()
    try:
        while menu_principal(db):
            pass
        ui.info("Sesión finalizada.")
    except KeyboardInterrupt:
        print()
        ui.advertencia("Sesión interrumpida por el operador.")
    except EOFError:
        print()
        ui.info("Entrada finalizada. Sesión cerrada.")
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
