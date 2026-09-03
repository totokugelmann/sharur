"""
Sharur SAIC - app/cli/consola.py

Modo consola interactivo: se siente como abrir una terminal en la
maquina donde estas trabajando, pero:

  - solo se pueden invocar los binarios de la allow-list
    (settings.CONSOLE_ALLOWED_BINARIES) -- nunca un shell libre;
  - cada linea ingresada pasa primero por gating_service (dispositivo
    / ventana temporal / operador autorizado) ANTES de ejecutarse;
  - toda ejecucion (autorizada o rechazada) queda auditada con hash
    de la evidencia cruda, via consola_service -> auditoria_service.

No hay pipes, redirecciones ni encadenado de shell: el input se
tokeniza con shlex.split() y se pasa como lista de argumentos
directo a subprocess.run(), nunca a traves de un shell.
"""

import shlex

from sqlalchemy.orm import Session

from app.cli import ui
from app.core.config import get_settings
from app.models.dispositivo import Dispositivo
from app.services import consola_service

settings = get_settings()


def _mostrar_ayuda() -> None:
    ui.subtitulo("Consola de comandos autorizados")
    ui.info("Binarios permitidos: " + ", ".join(settings.CONSOLE_ALLOWED_BINARIES))
    ui.info("Ejemplos: 'nmap -sV -F 192.0.2.10'   |   'whois example.com'   |   'dig example.com +noall +answer'")
    ui.info("Escribí 'salir' o 'exit' para volver al menú anterior.")
    ui.info("Cada línea que ejecutes queda registrada en la auditoría del caso, autorizada o no.")


def modo_consola(db: Session, caso_id: int, dispositivo: Dispositivo, username: str) -> None:
    ui.titulo(f"CONSOLA — dispositivo {dispositivo.identificador}")
    _mostrar_ayuda()

    while True:
        try:
            linea = input(f"\n  sharur({dispositivo.identificador})> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            ui.advertencia("Entrada interrumpida, volviendo al menú.")
            return

        if not linea:
            continue

        if linea.lower() in ("salir", "exit", "quit"):
            return

        if linea.lower() in ("ayuda", "help", "?"):
            _mostrar_ayuda()
            continue

        try:
            tokens = shlex.split(linea)
        except ValueError as exc:
            ui.error(f"No se pudo interpretar el comando: {exc}")
            continue

        if not tokens:
            continue

        binario, argumentos = tokens[0], tokens[1:]

        resultado = consola_service.ejecutar_comando_consola(
            db,
            caso_id=caso_id,
            dispositivo_id=dispositivo.id,
            username=username,
            binario=binario,
            argumentos=argumentos,
        )
        db.commit()

        if not resultado.autorizado:
            ui.error(f"Rechazado ({resultado.motivo_rechazo}).")
            if resultado.motivo_rechazo == "binario_fuera_de_allowlist":
                ui.info("Binarios permitidos: " + ", ".join(settings.CONSOLE_ALLOWED_BINARIES))
            continue

        print(resultado.stdout[:4000] or "(sin salida)")
        if resultado.stderr:
            ui.advertencia(f"stderr: {resultado.stderr[:500]}")
        ui.info(
            f"status={resultado.status} | {resultado.duracion_segundos:.2f}s | "
            f"hash evidencia: {(resultado.evidencia_hash or '-')[:16]}..."
        )
