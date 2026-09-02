"""
Sharur SAIC - app/services/tools_service.py

Ejecucion de herramientas automatizadas de reconocimiento, cada
una gateada individualmente.

Adaptado del tools.py original de Sharur: mismos principios
(subprocess.run con listas de argumentos, ToolResult estructurado,
sin shell=True), pero ahora cada ejecucion pasa primero por
gating_service y queda auditada por dispositivo/caso.
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
from app.services.gating_service import evaluar_gating


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
    "default": ["-sV", "-sC", "--top-ports", "1000", "-T4"],
    "rapido": ["-sV", "-F", "-T4"],
    "completo": ["-sV", "-sC", "-p-", "-T3"],
}


def _ejecutar_gateado(
    db: Session,
    caso_id: int,
    dispositivo_id: int,
    username: str,
    tool_name: str,
    command: List[str],
    timeout: int = 120,
) -> ToolResult:
    resultado_gating = evaluar_gating(db, dispositivo_id=dispositivo_id, username=username)

    if not resultado_gating.autorizado:
        auditoria_service.registrar_evento(
            db,
            caso_id=caso_id,
            tipo_evento=TipoEvento.ACCION_RECHAZADA_GATING,
            descripcion=f"Herramienta automatizada '{tool_name}' rechazada por gating.",
            actor_username=username,
            dispositivo_id=dispositivo_id,
            detalle={
                "tool": tool_name,
                "command": command,
                "motivo_rechazo": resultado_gating.motivo_rechazo,
            },
        )
        return ToolResult(
            tool=tool_name,
            command=command,
            status="rechazado_gating",
            output="",
            stderr=resultado_gating.detalle,
            duration_seconds=0.0,
            timeout_seconds=timeout,
        )

    resultado = _run_tool(command, tool_name, timeout=timeout)

    auditoria_service.registrar_evento(
        db,
        caso_id=caso_id,
        tipo_evento=TipoEvento.ACCION_AUTORIZADA,
        descripcion=f"Herramienta automatizada '{tool_name}' ejecutada (status={resultado.status}).",
        actor_username=username,
        dispositivo_id=dispositivo_id,
        detalle={
            "tool": tool_name,
            "command": command,
            "status": resultado.status,
            "duration_seconds": resultado.duration_seconds,
            "evidence_hash": resultado.evidence_hash,
        },
    )

    logger.info(
        "Herramienta %s ejecutada: caso=%s dispositivo=%s status=%s",
        tool_name,
        caso_id,
        dispositivo_id,
        resultado.status,
    )

    return resultado


def run_nmap(
    db: Session,
    caso_id: int,
    dispositivo_id: int,
    username: str,
    target: str,
    profile: str = "default",
) -> ToolResult:
    flags = NMAP_PROFILES.get(profile, NMAP_PROFILES["default"])
    command = ["nmap", *flags, target]
    timeout = 600 if profile == "completo" else 300
    return _ejecutar_gateado(db, caso_id, dispositivo_id, username, "nmap", command, timeout)


def run_whois(db: Session, caso_id: int, dispositivo_id: int, username: str, target: str) -> ToolResult:
    return _ejecutar_gateado(db, caso_id, dispositivo_id, username, "whois", ["whois", target], 60)


def run_dig(db: Session, caso_id: int, dispositivo_id: int, username: str, target: str) -> ToolResult:
    return _ejecutar_gateado(db, caso_id, dispositivo_id, username, "dig", ["dig", target, "+noall", "+answer"], 30)


def run_httpx(db: Session, caso_id: int, dispositivo_id: int, username: str, target: str) -> ToolResult:
    command = ["httpx", "-u", target, "-title", "-tech-detect", "-status-code", "-silent"]
    return _ejecutar_gateado(db, caso_id, dispositivo_id, username, "httpx", command, 60)


def run_testssl(db: Session, caso_id: int, dispositivo_id: int, username: str, target: str) -> ToolResult:
    command = ["testssl.sh", "--quiet", "--color", "0", target]
    return _ejecutar_gateado(db, caso_id, dispositivo_id, username, "testssl", command, 300)


def run_nuclei_deteccion(db: Session, caso_id: int, dispositivo_id: int, username: str, target: str) -> ToolResult:
    # Solo plantillas de deteccion pasiva de tecnologias/CVEs conocidos,
    # nunca plantillas de explotacion activa.
    command = ["nuclei", "-u", target, "-tags", "cve,tech", "-silent"]
    return _ejecutar_gateado(db, caso_id, dispositivo_id, username, "nuclei", command, 300)
