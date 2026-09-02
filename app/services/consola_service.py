"""
Sharur SAIC - app/services/consola_service.py

Consola manual de comandos de reconocimiento/analisis
autorizados.

Alcance deliberado: esta consola ejecuta herramientas de
reconocimiento y analisis pasivo/semi-activo (nmap, whois, dig,
curl, httpx, katana, nuclei con plantillas de deteccion, testssl,
graphw00f) contra dispositivos ya autorizados. NO es un entorno
de ejecucion de exploits ni de post-explotacion: el binario debe
estar en settings.CONSOLE_ALLOWED_BINARIES, lista que
deliberadamente no incluye frameworks de explotacion.

Cada invocacion:
1. Pasa por gating_service.evaluar_gating() - si rechaza, no se
   ejecuta nada y se audita el rechazo.
2. Verifica el binario contra la allow-list de settings.
3. Ejecuta con subprocess.run() y lista de argumentos (nunca
   shell=True, nunca concatenacion de strings).
4. El resultado (exitoso o no) queda auditado con hash de la
   salida cruda.
"""

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import List, Optional

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import logger
from app.core.security import sha256_of_text
from app.models.auditoria import TipoEvento
from app.services import auditoria_service
from app.services.gating_service import evaluar_gating

settings = get_settings()

DEFAULT_TIMEOUT_SECONDS = 120


@dataclass
class ResultadoComandoConsola:
    ejecutado: bool
    autorizado: bool
    binario: str
    argumentos: List[str]
    status: str = ""  # "ok" | "error" | "timeout" | "rechazado_gating" | "binario_no_permitido"
    stdout: str = ""
    stderr: str = ""
    duracion_segundos: float = 0.0
    motivo_rechazo: Optional[str] = None
    evidencia_hash: Optional[str] = None


def _binario_permitido(binario: str) -> bool:
    return binario in settings.CONSOLE_ALLOWED_BINARIES


def _binario_disponible(binario: str) -> bool:
    return shutil.which(binario) is not None


def ejecutar_comando_consola(
    db: Session,
    caso_id: int,
    dispositivo_id: int,
    username: str,
    binario: str,
    argumentos: List[str],
    notas: str = "",
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> ResultadoComandoConsola:
    # 1. Gating: dispositivo / tiempo / operador
    resultado_gating = evaluar_gating(db, dispositivo_id=dispositivo_id, username=username)

    if not resultado_gating.autorizado:
        auditoria_service.registrar_evento(
            db,
            caso_id=caso_id,
            tipo_evento=TipoEvento.ACCION_RECHAZADA_GATING,
            descripcion=f"Consola: comando '{binario}' rechazado por gating.",
            actor_username=username,
            dispositivo_id=dispositivo_id,
            detalle={
                "binario": binario,
                "argumentos": argumentos,
                "motivo_rechazo": resultado_gating.motivo_rechazo,
                "detalle_gating": resultado_gating.detalle,
            },
        )
        return ResultadoComandoConsola(
            ejecutado=False,
            autorizado=False,
            binario=binario,
            argumentos=argumentos,
            status="rechazado_gating",
            motivo_rechazo=resultado_gating.motivo_rechazo,
        )

    # 2. Allow-list de binarios (segunda barrera, independiente del gating)
    if not _binario_permitido(binario):
        auditoria_service.registrar_evento(
            db,
            caso_id=caso_id,
            tipo_evento=TipoEvento.ACCION_RECHAZADA_GATING,
            descripcion=f"Consola: binario '{binario}' no esta en la allow-list.",
            actor_username=username,
            dispositivo_id=dispositivo_id,
            detalle={"binario": binario, "argumentos": argumentos},
        )
        return ResultadoComandoConsola(
            ejecutado=False,
            autorizado=False,
            binario=binario,
            argumentos=argumentos,
            status="binario_no_permitido",
            motivo_rechazo="binario_fuera_de_allowlist",
        )

    if not _binario_disponible(binario):
        return ResultadoComandoConsola(
            ejecutado=False,
            autorizado=True,
            binario=binario,
            argumentos=argumentos,
            status="error",
            stderr=f"Binario '{binario}' no encontrado en el sistema.",
        )

    # 3. Ejecucion segura
    comando_completo = [binario, *argumentos]
    inicio = time.time()

    try:
        proceso = subprocess.run(
            comando_completo,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        duracion = time.time() - inicio
        status = "ok" if proceso.returncode == 0 else "error"
        stdout, stderr = proceso.stdout, proceso.stderr
    except subprocess.TimeoutExpired as exc:
        duracion = time.time() - inicio
        status = "timeout"
        stdout, stderr = (exc.stdout or ""), (exc.stderr or f"Timeout tras {timeout_seconds}s")
    except (OSError, subprocess.SubprocessError) as exc:
        duracion = time.time() - inicio
        status = "error"
        stdout, stderr = "", str(exc)

    evidencia_hash = sha256_of_text(stdout + "\n" + stderr)

    # 4. Auditoria del resultado (exitoso o no)
    auditoria_service.registrar_evento(
        db,
        caso_id=caso_id,
        tipo_evento=TipoEvento.ACCION_AUTORIZADA,
        descripcion=f"Consola: comando '{binario}' ejecutado (status={status}).",
        actor_username=username,
        dispositivo_id=dispositivo_id,
        detalle={
            "binario": binario,
            "argumentos": argumentos,
            "notas": notas,
            "status": status,
            "duracion_segundos": duracion,
            "evidencia_hash": evidencia_hash,
        },
    )

    logger.info(
        "Consola: caso=%s dispositivo=%s binario=%s status=%s duracion=%.2fs",
        caso_id,
        dispositivo_id,
        binario,
        status,
        duracion,
    )

    return ResultadoComandoConsola(
        ejecutado=True,
        autorizado=True,
        binario=binario,
        argumentos=argumentos,
        status=status,
        stdout=stdout,
        stderr=stderr,
        duracion_segundos=duracion,
        evidencia_hash=evidencia_hash,
    )
