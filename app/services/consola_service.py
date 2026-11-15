"""
Sharur SAIC - app/services/consola_service.py

Consola manual interactiva (Modo PoC).
"""

import re
import shlex
import shutil
import subprocess
import time
import sys
from dataclasses import dataclass
from typing import List, Optional

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import logger
from app.core.security import sha256_of_text
from app.models.auditoria import TipoEvento
from app.services import auditoria_service

settings = get_settings()

@dataclass
class ResultadoComandoConsola:
    ejecutado: bool
    binario: str
    argumentos: List[str]
    status: str = ""  # "ok" | "error" | "timeout" | "comando_prohibido" | "target_invalido"
    stdout: str = ""
    stderr: str = ""
    duracion_segundos: float = 0.0
    motivo_rechazo: Optional[str] = None
    evidencia_hash: Optional[str] = None


def _contiene_patron_prohibido(comando_str: str) -> Optional[str]:
    for patron in settings.CONSOLE_BANNED_PATTERNS:
        if re.search(patron, comando_str):
            return f"El comando contiene un patrón prohibido: {patron}"
    return None


def ejecutar_comando_consola(
    db: Session,
    caso_id: int,
    username: str,
    target_ip: str,
    comando_str: str,
) -> ResultadoComandoConsola:
    
    motivo_bloqueo = _contiene_patron_prohibido(comando_str)
    if motivo_bloqueo:
        auditoria_service.registrar_evento(
            db, caso_id=caso_id, tipo_evento=TipoEvento.ACCION_RECHAZADA_GATING,
            descripcion=f"Consola: comando bloqueado por política.",
            actor_username=username, detalle={"comando": comando_str, "motivo": motivo_bloqueo}
        )
        return ResultadoComandoConsola(
            ejecutado=False, binario="DESCONOCIDO", argumentos=[],
            status="comando_prohibido", motivo_rechazo=motivo_bloqueo
        )

    try:
        tokens = shlex.split(comando_str)
    except ValueError as e:
        return ResultadoComandoConsola(False, "", [], status="error", stderr=f"Error de sintaxis: {e}")
        
    if not tokens:
        return ResultadoComandoConsola(False, "", [], status="error", stderr="Comando vacío.")

    binario = tokens[0]
    argumentos = tokens[1:]

    if binario in settings.CONSOLE_BANNED_BINARIES:
        auditoria_service.registrar_evento(
            db, caso_id=caso_id, tipo_evento=TipoEvento.ACCION_RECHAZADA_GATING,
            descripcion=f"Consola: binario destructivo '{binario}' bloqueado.",
            actor_username=username, detalle={"comando": comando_str}
        )
        return ResultadoComandoConsola(
            ejecutado=False, binario=binario, argumentos=argumentos,
            status="comando_prohibido", motivo_rechazo="binario_en_lista_negra"
        )

    # Validar target
    ips_en_comando = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', comando_str)
    if not ips_en_comando and target_ip not in comando_str:
        return ResultadoComandoConsola(
            ejecutado=False, binario=binario, argumentos=argumentos,
            status="target_invalido", motivo_rechazo=f"El comando debe incluir el target: {target_ip}"
        )
    for ip in ips_en_comando:
        if ip != target_ip:
            return ResultadoComandoConsola(
                ejecutado=False, binario=binario, argumentos=argumentos,
                status="target_invalido", motivo_rechazo=f"Intento de atacar a {ip}. Tu target es {target_ip}."
            )

    if not shutil.which(binario):
        return ResultadoComandoConsola(False, binario, argumentos, status="error", stderr=f"Binario '{binario}' no instalado.")

    # Ejecución interactiva (permite nc, msfconsole, etc.)
    print(f"\n[Ejecutando: {comando_str}]")
    print("[Presioná Ctrl+C para abortar el comando, o 'exit' si es una shell interactiva]")
    
    inicio = time.time()
    status = "ok"
    
    try:
        # Usamos Popen para que herede la terminal (stdin/stdout/stderr directos)
        proceso = subprocess.Popen(
            [binario, *argumentos],
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr
        )
        proceso.wait() # Espera a que termine
        
        if proceso.returncode != 0:
            status = "error"
            
    except KeyboardInterrupt:
        # Si el usuario aprieta Ctrl+C, matamos el proceso hijo y seguimos vivos
        print("\n[!] Comando abortado por el operador (Ctrl+C).")
        try:
            proceso.terminate()
            proceso.wait(timeout=2)
        except Exception:
            proceso.kill()
        status = "abortado"
        
    except Exception as exc:
        status = "error"
        print(f"\n[!] Error al ejecutar: {exc}")

    duracion = time.time() - inicio
    # Al usar salida interactiva, no capturamos el stdout para el hash,
    # pero dejamos constancia del comando ejecutado en la auditoría.
    evidencia_hash = sha256_of_text(comando_str + str(duracion))

    auditoria_service.registrar_evento(
        db, caso_id=caso_id, tipo_evento=TipoEvento.ACCION_AUTORIZADA,
        descripcion=f"Consola interactiva: '{comando_str}' finalizado (status={status}).",
        actor_username=username,
        detalle={"binario": binario, "target": target_ip, "status": status, "evidencia_hash": evidencia_hash}
    )

    return ResultadoComandoConsola(
        ejecutado=True, binario=binario, argumentos=argumentos,
        status=status, duracion_segundos=duracion, evidencia_hash=evidencia_hash
    )
