"""
Sharur SAIC - app/services/network_control.py

Control de red por allow-list: restringe ambientalmente el
trafico saliente de la consola/herramientas a solo los
identificadores de dispositivo cargados como alcance autorizado
de un caso.

Esto es una capa adicional al gating logico (gating_service.py):
el gating decide "esta accion esta autorizada", este modulo
asegura que, incluso si algo se ejecutara sin pasar por el
gating por error de programacion en otra capa, el paquete de
red simplemente no puede salir hacia un destino no autorizado.

Implementacion de referencia con iptables. En produccion esto
deberia correr con privilegios administrados (ej: un sidecar con
CAP_NET_ADMIN) y nunca con la app principal corriendo como root.
"""

import shlex
import subprocess
from dataclasses import dataclass
from typing import List

from app.core.config import get_settings
from app.core.logging import logger
from app.core.utils import is_valid_cidr, is_valid_ip

settings = get_settings()

# Prefijo de las cadenas iptables que administra Sharur, para no
# tocar reglas ajenas del sistema.
CHAIN_PREFIX = "SHARUR_CASO_"


@dataclass
class ResultadoNetworkControl:
    ok: bool
    detalle: str
    comando: List[str] = None


def _chain_name(caso_id: int) -> str:
    return f"{CHAIN_PREFIX}{caso_id}"


def _run(command: List[str]) -> ResultadoNetworkControl:
    if settings.NETWORK_CONTROL_BACKEND == "noop":
        logger.info("network_control en modo noop, comando simulado: %s", shlex.join(command))
        return ResultadoNetworkControl(ok=True, detalle="modo noop (sin cambios reales de red)", comando=command)

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    except (subprocess.SubprocessError, FileNotFoundError) as exc:
        logger.error("Fallo ejecutando comando de network_control: %s", exc)
        return ResultadoNetworkControl(ok=False, detalle=str(exc), comando=command)

    if result.returncode != 0:
        return ResultadoNetworkControl(
            ok=False,
            detalle=f"returncode={result.returncode} stderr={result.stderr.strip()}",
            comando=command,
        )

    return ResultadoNetworkControl(ok=True, detalle="ejecutado correctamente", comando=command)


def inicializar_perimetro_caso(caso_id: int) -> ResultadoNetworkControl:
    """
    Crea una cadena iptables dedicada al caso, con politica DROP
    por defecto. Se deben agregar reglas ACCEPT explicitas por
    cada dispositivo autorizado (ver permitir_destino).
    """
    chain = _chain_name(caso_id)
    crear = _run(["sudo", "iptables", "-N", chain])
    politica_drop = _run(["sudo", "iptables", "-A", chain, "-j", "DROP"])
    enlazar = _run(["sudo", "iptables", "-I", "OUTPUT", "-j", chain])

    ok = crear.ok and politica_drop.ok and enlazar.ok
    return ResultadoNetworkControl(
        ok=ok,
        detalle=f"perimetro caso {caso_id}: crear={crear.detalle}, drop={politica_drop.detalle}, enlazar={enlazar.detalle}",
    )


def permitir_destino(caso_id: int, identificador: str) -> ResultadoNetworkControl:
    """
    Agrega una regla ACCEPT para un identificador de dispositivo
    (IP o CIDR) dentro de la cadena del caso, ANTES de la regla
    DROP final.

    Dominios no se resuelven aca: la resolucion DNS y su snapshot
    quedan a cargo del modulo de reconocimiento (tools_service /
    export), que ya registra la IP resuelta en la evidencia.
    """
    if not (is_valid_ip(identificador) or is_valid_cidr(identificador)):
        return ResultadoNetworkControl(
            ok=False,
            detalle=f"'{identificador}' no es una IP ni un CIDR valido; no se puede aplicar allow-list de red directamente (usar IP resuelta).",
        )

    chain = _chain_name(caso_id)
    # Inserta al inicio de la cadena (antes del DROP final agregado en init)
    comando = ["sudo", "iptables", "-I", chain, "1", "-d", identificador, "-j", "ACCEPT"]
    resultado = _run(comando)
    logger.info(
        "network_control: permitir_destino caso=%s destino=%s ok=%s",
        caso_id,
        identificador,
        resultado.ok,
    )
    return resultado


def revocar_destino(caso_id: int, identificador: str) -> ResultadoNetworkControl:
    chain = _chain_name(caso_id)
    comando = ["sudo", "iptables", "-D", chain, "-d", identificador, "-j", "ACCEPT"]
    return _run(comando)


def desmontar_perimetro_caso(caso_id: int) -> ResultadoNetworkControl:
    """
    Se invoca al cierre del caso: desengancha y elimina la cadena
    dedicada. Debe llamarse solo despues de que todos los
    dispositivos del caso tengan cese ejecutado.
    """
    chain = _chain_name(caso_id)
    desenlazar = _run(["sudo", "iptables", "-D", "OUTPUT", "-j", chain])
    vaciar = _run(["sudo", "iptables", "-F", chain])
    eliminar = _run(["sudo", "iptables", "-X", chain])

    ok = desenlazar.ok and vaciar.ok and eliminar.ok
    return ResultadoNetworkControl(
        ok=ok,
        detalle=f"perimetro caso {caso_id} desmontado: {ok}",
    )
