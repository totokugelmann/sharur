#!/usr/bin/env python3
"""
Sharur SAIC - sharur_cli.py

Punto de entrada del CLI interactivo, en el espiritu del METATRON
original: un flujo de terminal que va guiando al operador paso a
paso, en vez de una API que hay que golpear con curl.

Flujo:
  1. Identificación del operador
  2. Creación o selección de un Caso
  3. Carga u obtención de la Orden judicial y su alcance (límites):
     ordenes, personal autorizado, dispositivos
  4. Selección del dispositivo a intervenir
  5. Menú principal de análisis: herramientas numeradas (nmap,
     whois, dig, httpx, testssl, nuclei), más las opciones de
     hallazgos / auditoría / cese, y al final de la lista, la
     consola de comandos autorizados.

Toda la logica de negocio (gating, auditoria, evidence-first)
vive en app/services/ -- este script es solo la interfaz de
terminal sobre esos mismos servicios que tambien usa la API HTTP.

Uso:
    python sharur_cli.py

Requiere: DATABASE_URL configurada (.env) apuntando a una base ya
migrada (`alembic upgrade head`). Para la opción de análisis con
IA hace falta ademas Ollama corriendo con el modelo `sharur-qwen`
(ver README, sección "Setup de desarrollo").
"""

import sys

from app.cli import sesion, ui
from app.cli.menu_analisis import menu_intervencion
from app.models.base import SessionLocal


def main() -> None:
    db = SessionLocal()

    try:
        username = sesion.identificar_operador()

        caso = sesion.elegir_o_crear_caso(db, username)
        if caso is None:
            ui.error("No se pudo determinar un caso para operar. Saliendo.")
            return

        orden = sesion.elegir_o_cargar_orden(db, caso, username)
        if orden is None:
            ui.error("No se pudo determinar una orden para operar. Saliendo.")
            return

        while True:
            dispositivo = sesion.elegir_dispositivo(db, orden, username)
            if dispositivo is None:
                ui.info("No hay dispositivo seleccionado. Volviendo a elegir caso/orden.")
                orden = sesion.elegir_o_cargar_orden(db, caso, username)
                if orden is None:
                    break
                continue

            menu_intervencion(db, caso.id, orden, dispositivo, username)

            if not ui.prompt_si_no("¿Operar sobre otro dispositivo de esta misma orden?", default=True):
                break

        ui.titulo("Sesión finalizada")
        if ui.prompt_si_no(f"¿Cerrar el caso #{caso.id} ahora?", default=False):
            from app.services import caso_service

            motivo = ui.prompt("Motivo de cierre")
            try:
                caso_service.cerrar_caso(db, caso, motivo_cierre=motivo, cerrado_por=username)
                db.commit()
                ui.ok("Caso cerrado. Hash de reporte final generado.")
            except ValueError as exc:
                ui.error(str(exc))
        else:
            ui.info(f"El caso #{caso.id} queda abierto para continuar en otra sesión.")

    except KeyboardInterrupt:
        print()
        ui.advertencia("Sesión interrumpida por el operador.")
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
