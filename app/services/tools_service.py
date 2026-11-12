"""
Sharur SAIC - app/services/tools_service.py

Ejecucion de herramientas automatizadas de reconocimiento.
Adaptado para operar a nivel de Caso (sin dispositivo_id obligatorio).
"""

import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import List

from sqlalchemy.orm import Session

from app.core.logging import logger
from app.core.security import sha256_of_text
from app.models.auditoria import TipoEvento
from app.services import auditoria_service


@dataclass
class ToolResult:
    tool: str
    command: List[str]
    status: str  # "ok" | "error" | "timeout" | "not_found"
    output: str
    stderr: str
    duration_seconds: float
    timeout_seconds: int
    evidence_hash: str = ""

    def to_text(self) -> str:
        return (
            f"TOOL: {self.tool}\n"
            f"COMMAND: {shlex.join(self.command)}\n"
            f"STATUS: {self.status}\n"
            f"DURATION: {self.duration_seconds:.2f}s\n"
            f"OUTPUT:\n{self.output}\n"
            f"STDERR:\n{self.stderr}\n"
        )


def _tool_exists(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None


def _run_tool(command: List[str], tool_name: str, timeout: int = 120) -> ToolResult:
    if not _tool_exists(command[0]):
        return ToolResult(
            tool=tool_name,
            command=command,
            status="not_found",
            output="",
            stderr=f"Binario '{command[0]}' no disponible en el sistema.",
            duration_seconds=0.0,
            timeout_seconds=timeout,
        )

    inicio = time.time()
    try:
        proceso = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        duracion = time.time() - inicio
        status = "ok" if proceso.returncode == 0 else "error"
        stdout, stderr = proceso.stdout, proceso.stderr
    except subprocess.TimeoutExpired as exc:
        duracion = time.time() - inicio
        status = "timeout"
        stdout, stderr = (exc.stdout or ""), (exc.stderr or f"Timeout tras {timeout}s")
    except (OSError, subprocess.SubprocessError) as exc:
        duracion = time.time() - inicio
        status = "error"
        stdout, stderr = "", str(exc)

    return ToolResult(
        tool=tool_name,
        command=command,
        status=status,
        output=stdout,
        stderr=stderr,
        duration_seconds=duracion,
        timeout_seconds=timeout,
        evidence_hash=sha256_of_text(stdout + "\n" + stderr),
    )


NMAP_PROFILES = {
    # Perfiles para escaneo de redes (descubrimiento)
    "red_descubrimiento": ["-sn"],
    "red_agresivo": ["-Pn", "-PS22,80,443,445,3389", "-T4", "--max-retries", "1"],
    
    # Perfiles para escaneo de objetivos (puertos/servicios)
    "obj_default": ["-sV", "-sC", "--top-ports", "1000", "-T4"],
    "obj_rapido": ["-sV", "-F", "-T4"],
    "obj_completo": ["-sV", "-sC", "-p-", "-T3"],
    "obj_sigiloso": ["-sS", "-T2", "--top-ports", "100"],
}


def _ejecutar_auditada(
    db: Session,
    caso_id: int,
    username: str,
    tool_name: str,
    command: List[str],
    timeout: int = 120,
) -> ToolResult:
    """
    Ejecuta la herramienta, firma el resultado y lo registra en la
    cadena de auditoría del caso.
    """
    resultado = _run_tool(command, tool_name, timeout=timeout)

    auditoria_service.registrar_evento(
        db,
        caso_id=caso_id,
        tipo_evento=TipoEvento.ACCION_AUTORIZADA,
        descripcion=f"Herramienta '{tool_name}' ejecutada (status={resultado.status}).",
        actor_username=username,
        detalle={
            "tool": tool_name,
            "command": command,
            "status": resultado.status,
            "duration_seconds": resultado.duration_seconds,
            "evidence_hash": resultado.evidence_hash,
        },
    )

    logger.info(
        "Herramienta %s ejecutada: caso=%s status=%s",
        tool_name,
        caso_id,
        resultado.status,
    )

    return resultado


def run_nmap(
    db: Session,
    caso_id: int,
    username: str,
    target: str,
    profile: str = "obj_default",
) -> ToolResult:
    flags = NMAP_PROFILES.get(profile, NMAP_PROFILES["obj_default"])
    command = ["nmap", *flags, target]
    timeout = 600 if "completo" in profile else 300
    return _ejecutar_auditada(db, caso_id, username, "nmap", command, timeout)


def run_arp_scan(db: Session, caso_id: int, username: str, target: str) -> ToolResult:
    command = ["arp-scan", target]
    return _ejecutar_auditada(db, caso_id, username, "arp-scan", command, 120)


def run_netdiscover(db: Session, caso_id: int, username: str, target: str) -> ToolResult:
    command = ["netdiscover", "-r", target, "-P"]
    return _ejecutar_auditada(db, caso_id, username, "netdiscover", command, 120)
