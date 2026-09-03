"""
Sharur SAIC - app/cli/menu_analisis.py

Menu principal de intervencion sobre un dispositivo ya
seleccionado: las herramientas automatizadas de reconocimiento
numeradas, y al final de la lista, la consola.

Cada opcion pasa por evaluar_gating() antes de ejecutar (ya
resuelto dentro de tools_service / consola_service / gating_service
-- este modulo no reimplementa esa logica, solo la presenta como
menu).
"""

from sqlalchemy.orm import Session

from app.cli import ui
from app.cli.consola import modo_consola
from app.models.dispositivo import Dispositivo
from app.models.orden import Orden
from app.services import (
    analisis_ia_service,
    auditoria_service,
    cese_service,
    notificacion_service,
    tools_service,
)
from app.services.tools_service import ToolResult

# Orden de la lista tal como la ve el operador. El primer elemento
# de cada tupla es la etiqueta de menu; el segundo, la funcion de
# tools_service ya gateada que ejecuta la herramienta.
_HERRAMIENTAS = [
    ("nmap", "nmap — reconocimiento de puertos y servicios", tools_service.run_nmap),
    ("whois", "whois — datos de registro del dominio/IP", tools_service.run_whois),
    ("dig", "dig — resolución DNS", tools_service.run_dig),
    ("httpx", "httpx — detección de tecnologías HTTP", tools_service.run_httpx),
    ("testssl", "testssl — análisis de configuración TLS/SSL", tools_service.run_testssl),
    ("nuclei", "nuclei — detección de CVEs/tecnologías conocidas", tools_service.run_nuclei_deteccion),
]


def _elegir_objetivo(dispositivo: Dispositivo) -> str:
    """
    Pregunta el objetivo a usar para el escaneo. Por defecto sugiere
    el identificador del dispositivo, pero si hay un rango de red
    autorizado cargado (IP dinamica, se necesita localizar el
    dispositivo), lo ofrece como alternativa -- y de todos modos deja
    escribir cualquier otro valor dentro de lo que la orden autoriza.

    La verificacion de que el equipo hallado en el objetivo elegido es
    efectivamente el dispositivo autorizado es responsabilidad manual
    del operador (revisando MAC/hostname/fingerprint en la evidencia
    despues), el sistema no lo automatiza.
    """
    if dispositivo.rango_red_autorizado:
        ui.info(
            f"  Identificador registrado: {dispositivo.identificador} | "
            f"Rango de red autorizado: {dispositivo.rango_red_autorizado}"
        )
        ui.info("  Usá el identificador si conocés la IP exacta, o el rango para localizar el dispositivo.")
        return ui.prompt("  Objetivo del escaneo", default=dispositivo.rango_red_autorizado)

    return ui.prompt("  Objetivo del escaneo", default=dispositivo.identificador)


def _elegir_perfil_nmap() -> str:
    opciones = [
        ("default", "default — balance estándar (-sV -sC --top-ports 1000)"),
        ("rapido", "rápido — top puertos más comunes, veloz (-sV -F)"),
        ("completo", "completo — los 65535 puertos, más lento (-sV -sC -p-)"),
        ("sigiloso", "sigiloso — SYN scan lento, menos detectable (-sS -T2, requiere privilegios)"),
    ]
    return ui.menu("Perfil de escaneo (nmap)", opciones)


def _mostrar_resultado_tool(resultado: ToolResult) -> None:
    ui.subtitulo(f"Resultado: {resultado.tool} (status={resultado.status})")
    if resultado.status == "rechazado_gating":
        ui.error(f"Rechazado por gating: {resultado.stderr}")
        return
    if resultado.status == "not_found":
        ui.error(resultado.stderr)
        return

    print(resultado.output[:4000] or "(sin salida)")
    if resultado.stderr:
        ui.advertencia(f"stderr: {resultado.stderr[:500]}")
    ui.info(f"Duración: {resultado.duration_seconds:.2f}s | hash evidencia: {resultado.evidence_hash[:16]}...")


def _ejecutar_herramienta(db: Session, caso_id: int, dispositivo: Dispositivo, username: str, codigo: str, fn) -> None:
    target = _elegir_objetivo(dispositivo)

    if codigo == "nmap":
        perfil = _elegir_perfil_nmap()
        resultado = fn(db, caso_id, dispositivo.id, username, target, profile=perfil)
    else:
        resultado = fn(db, caso_id, dispositivo.id, username, target)

    db.commit()
    _mostrar_resultado_tool(resultado)

    if resultado.status == "ok" and ui.prompt_si_no(
        "¿Enviar esta evidencia al modelo de IA para sugerir CVEs aplicables?", default=True
    ):
        _analisis_ia_sobre_resultado(db, caso_id, dispositivo, username, codigo, resultado)


def _analisis_ia_sobre_resultado(db: Session, caso_id: int, dispositivo: Dispositivo, username: str, herramienta: str, resultado_tool) -> None:
    ui.info("Consultando al modelo local (Ollama) y verificando contra NVD, puede tardar unos segundos...")
    try:
        hallazgos = analisis_ia_service.analizar_evidencia(
            db, caso_id=caso_id, dispositivo_id=dispositivo.id, username=username,
            herramienta=herramienta, resultado_tool=resultado_tool,
        )
        db.commit()
    except ValueError as exc:
        ui.error(str(exc))
        return

    if not hallazgos:
        ui.info("El modelo no propuso ningún hallazgo verificable sobre esta evidencia.")
        return

    filas = [
        [h.id, h.cve_id or "-", h.severidad.value, h.confianza.value, h.titulo[:40]]
        for h in hallazgos
    ]
    ui.tabla(["ID", "CVE", "Severidad", "Confianza", "Título"], filas)


def _ver_hallazgos(db: Session, dispositivo: Dispositivo) -> None:
    from app.models.notificacion import Hallazgo

    hallazgos = (
        db.query(Hallazgo)
        .filter(Hallazgo.dispositivo_id == dispositivo.id)
        .order_by(Hallazgo.id.desc())
        .all()
    )
    ui.subtitulo(f"Hallazgos registrados — dispositivo {dispositivo.identificador}")
    filas = [
        [h.id, h.cve_id or "-", h.severidad.value, h.confianza.value, h.herramienta_origen, h.titulo[:35]]
        for h in hallazgos
    ]
    ui.tabla(["ID", "CVE", "Severidad", "Confianza", "Herramienta", "Título"], filas)


def _ver_auditoria(db: Session, caso_id: int) -> None:
    from app.models.auditoria import EventoAuditoria

    eventos = (
        db.query(EventoAuditoria)
        .filter(EventoAuditoria.caso_id == caso_id)
        .order_by(EventoAuditoria.secuencia.desc())
        .limit(25)
        .all()
    )
    ui.subtitulo("Últimos 25 eventos de auditoría (más reciente primero)")
    filas = [
        [e.secuencia, e.tipo_evento.value, e.actor_username or "-", e.descripcion[:50]]
        for e in eventos
    ]
    ui.tabla(["Seq", "Tipo", "Actor", "Descripción"], filas)

    if ui.prompt_si_no("¿Verificar integridad de la cadena de hashes?", default=False):
        resultado = auditoria_service.verificar_cadena(db, caso_id)
        if resultado["integra"]:
            ui.ok(f"Cadena íntegra. Total de eventos: {resultado['total_eventos']}")
        else:
            ui.error(f"CADENA ALTERADA: {resultado['detalle']}")


def _ejecutar_cese(db: Session, dispositivo: Dispositivo, username: str) -> bool:
    ui.subtitulo(f"Cese sobre dispositivo {dispositivo.identificador}")
    if not ui.prompt_si_no("¿Confirmás que el objetivo se cumplió y se debe ejecutar el cese?", default=False):
        return False

    notas = ui.prompt("Notas del cese", requerido=False)
    try:
        cese_service.ejecutar_cese(db, dispositivo, ejecutado_por=username, actor_username=username, notas=notas or None)
        db.commit()
    except ValueError as exc:
        ui.error(str(exc))
        return False

    ui.ok("Cese registrado. El dispositivo queda bloqueado para nuevas acciones (gating).")

    if ui.prompt_si_no("¿Generar la notificación al imputado/defensor ahora?", default=True):
        rol = ui.prompt("Destinatario: 'imputado' o 'defensor'", default="defensor")
        nombre = ui.prompt("Nombre del destinatario")
        notif = notificacion_service.generar_notificacion(
            db, dispositivo, destinatario_nombre=nombre, destinatario_rol=rol, actor_username=username
        )
        db.commit()
        ui.ok(f"Notificación generada (id={notif.id}, hash={notif.hash_contenido[:16]}...).")

    return True


def menu_intervencion(db: Session, caso_id: int, orden: Orden, dispositivo: Dispositivo, username: str) -> None:
    while True:
        opciones = [(codigo, etiqueta) for codigo, etiqueta, _ in _HERRAMIENTAS]
        opciones += [
            ("hallazgos", "Ver hallazgos registrados en este dispositivo"),
            ("auditoria", "Ver auditoría del caso"),
            ("cese", "Ejecutar cese sobre este dispositivo"),
            ("cambiar_dispositivo", "Cambiar de dispositivo"),
            ("consola", "Consola (comandos autorizados, todo queda registrado)"),
            ("salir", "Salir"),
        ]

        titulo_menu = f"Caso #{caso_id} · Orden {orden.numero_orden} · Dispositivo {dispositivo.identificador}"
        eleccion = ui.menu(titulo_menu, opciones)

        if eleccion == "salir":
            if ui.confirmar_salida():
                return
            continue

        if eleccion == "cambiar_dispositivo":
            return  # el caller (main) vuelve a pedir dispositivo

        if eleccion == "hallazgos":
            _ver_hallazgos(db, dispositivo)
            ui.pausar()
            continue

        if eleccion == "auditoria":
            _ver_auditoria(db, caso_id)
            ui.pausar()
            continue

        if eleccion == "cese":
            cesado = _ejecutar_cese(db, dispositivo, username)
            ui.pausar()
            if cesado:
                return  # el dispositivo ya no admite mas acciones, volver a elegir otro
            continue

        if eleccion == "consola":
            modo_consola(db, caso_id, dispositivo, username)
            continue

        # Es una herramienta de la lista numerada
        for codigo, _, fn in _HERRAMIENTAS:
            if codigo == eleccion:
                _ejecutar_herramienta(db, caso_id, dispositivo, username, codigo, fn)
                ui.pausar()
                break
