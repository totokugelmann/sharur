"""
Sharur SAIC - app/cli/menu_analisis.py

Menú principal de análisis, dentro de un caso abierto.
- Redes: descubrimiento de hosts (con opción de enriquecimiento por IA).
- Objetivos: escaneo profundo y análisis automático con IA + NVD.
- Consola libre: comandos interactivos auditados.
- Auditoría, informe y cierre.

Toda la presentación pasa por app.cli.ui (rich). La lógica y las
llamadas a los servicios no cambian respecto del núcleo auditable.
"""

import socket

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.cli import ui
from app.models.caso import Caso
from app.services import tools_service


def _prompt(msg: str, default: str = None) -> str:
    return ui.pedir(msg, default=default, obligatorio=default is None)


def _pausar() -> None:
    ui.pausar()


def _get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def _pie_tool(res) -> str:
    return f"Duración: {res.duration_seconds:.2f}s   |   Hash evidencia: {res.evidence_hash[:16]}..."


def _mostrar_auditoria(db: Session, caso: Caso) -> None:
    from app.models.auditoria import EventoAuditoria

    eventos = (
        db.query(EventoAuditoria)
        .filter(EventoAuditoria.caso_id == caso.id)
        .order_by(EventoAuditoria.secuencia.desc())
        .limit(25)
        .all()
    )
    ui.titulo(f"ÚLTIMOS 25 EVENTOS DE AUDITORÍA", f"Caso #{caso.id} · {caso.numero_causa}")
    if not eventos:
        ui.info("(sin eventos)")
        return
    ui.tabla_auditoria(eventos)


# ─────────────────────────────────────────────
# Consola Libre (Modo PoC / interactivo)
# ─────────────────────────────────────────────

def _consola_libre(db: Session, caso: Caso) -> None:
    from app.services import consola_service

    ui.titulo("CONSOLA LIBRE", "Modo interactivo auditado")
    ui.info("Cada línea queda registrada en la cadena de auditoría del caso, autorizada o no.")

    target_ip = ui.pedir("IP/Dominio objetivo autorizado para esta sesión", obligatorio=False)
    if not target_ip:
        ui.advertencia("Target vacío. Volviendo al menú.")
        return

    ui.info(f"Target fijado en: {target_ip}")
    ui.nota("Escribí 'salir' para volver al menú principal.")

    while True:
        try:
            comando = ui.pedir(f"sharur({target_ip})", obligatorio=False)

            if not comando:
                continue
            if comando.lower() in ["salir", "exit", "quit"]:
                break

            res = consola_service.ejecutar_comando_consola(
                db, caso_id=caso.id, username=caso.creado_por,
                target_ip=target_ip, comando_str=comando
            )
            db.commit()

            if res.status in ["binario_no_permitido", "target_invalido", "comando_prohibido"]:
                ui.error(f"COMANDO BLOQUEADO: {res.motivo_rechazo}")

        except KeyboardInterrupt:
            # Ctrl+C en el prompt (sin ejecutar nada): no cierra Sharur.
            print()
            ui.nota("(Usá 'salir' para volver al menú principal)")
            continue
        except Exception as exc:
            ui.error(f"Error inesperado: {exc}")


# ─────────────────────────────────────────────
# Exportar informe
# ─────────────────────────────────────────────

def _exportar_informe(db: Session, caso: Caso) -> None:
    from app.services import reporte_service

    opcion = ui.menu(
        "Exportar informe del caso",
        [
            ("1", "HTML"),
            ("2", "PDF", "si hay motor; si no, cae a HTML"),
            ("3", "Volver"),
        ],
        prompt="Formato",
    )
    if opcion == "3":
        return
    formato = "pdf" if opcion == "2" else "html"
    try:
        with ui.spinner("Generando informe del caso..."):
            res = reporte_service.exportar_informe(db, caso, formato=formato)
        db.commit()
        ui.exito(f"Informe generado: {res['ruta']}")
        ui.nota(f"Formato: {res['formato']}   |   SHA-256: {res['hash_sha256']}")
        if not res.get("auditado", True):
            ui.info("El evento no se registró en la auditoría (ver logs); el informe es válido.")
    except Exception as exc:
        db.rollback()
        ui.error(f"No se pudo exportar el informe: {exc}")


# ─────────────────────────────────────────────
# Lógica de Escaneo Enriquecido (IA)
# ─────────────────────────────────────────────

def _ejecutar_enriquecido(db: Session, caso: Caso, target: str, herramienta_base: str) -> None:
    from app.services import analisis_ia_service

    ui.info(f"Fase 1: ejecutando {herramienta_base} base...")
    res_base = None
    if herramienta_base == "arp-scan":
        res_base = tools_service.run_arp_scan(db, caso_id=caso.id, username=caso.creado_por, target=target)
    elif herramienta_base == "netdiscover":
        res_base = tools_service.run_netdiscover(db, caso_id=caso.id, username=caso.creado_por, target=target)
    elif herramienta_base == "nmap":
        res_base = tools_service.run_nmap(db, caso_id=caso.id, username=caso.creado_por, target=target, profile="red_basico")

    if not res_base or res_base.status != "ok":
        ui.error("Falló el escaneo base.")
        return

    ui.info("Fase 2: buscando huellas de dispositivos (puertos clave)...")
    res_puertos = tools_service.run_nmap(
        db, caso_id=caso.id, username=caso.creado_por, target=target, profile="red_identificacion"
    )
    db.commit()

    try:
        with ui.spinner("Fase 3: la IA está analizando MACs y puertos..."):
            dispositivos = analisis_ia_service.identificar_dispositivos_red(
                db, caso_id=caso.id, username=caso.creado_por,
                resultado_arp=res_base, resultado_nmap_puertos=res_puertos
            )
    except Exception as exc:
        ui.error(f"Error consultando a la IA: {exc}")
        return

    if not dispositivos:
        ui.info("La IA no pudo identificar dispositivos (o la red está vacía).")
        return

    lineas = []
    for d in dispositivos:
        conf = (d.get("confianza") or "").upper()
        lineas.append(f"IP: {d.get('ip')}   |   MAC: {d.get('mac')}")
        lineas.append(f"  TIPO: {d.get('tipo')}  (Confianza: {conf})")
        lineas.append(f"  RAZÓN: {d.get('razon')}")
        lineas.append("")
    ui.panel("\n".join(lineas).rstrip(), cabecera="INVENTARIO DE DISPOSITIVOS IDENTIFICADOS", estilo=ui.OK)


# ─────────────────────────────────────────────
# Submenús de Redes
# ─────────────────────────────────────────────

def _menu_nmap_redes(db: Session, caso: Caso, target: str) -> None:
    while True:
        op = ui.menu(
            "Perfiles de Nmap (Redes)",
            [
                ("1", "Básico", "-sn · ping scan estándar"),
                ("2", "Rápido", "-sn -T4 -n · ping rápido sin DNS"),
                ("3", "Profundo", "-Pn -PS... · fuerza TCP SYN, atraviesa firewalls"),
                ("4", "Sigiloso", "-sn -T2 · ping lento, menos ruido"),
                ("5", "Enriquecido", "escaneo + IA para identificar dispositivos"),
                ("6", "Volver"),
            ],
        )

        if op == "6":
            return
        if op not in ["1", "2", "3", "4", "5"]:
            ui.advertencia("Opción inválida.")
            continue

        if op == "5":
            _ejecutar_enriquecido(db, caso, target, "nmap")
            _pausar()
            return

        perfil = {"1": "red_basico", "2": "red_rapido", "3": "red_profundo", "4": "red_sigiloso"}[op]
        with ui.spinner(f"Ejecutando nmap ({perfil}) en {target}..."):
            res = tools_service.run_nmap(db, caso_id=caso.id, username=caso.creado_por, target=target, profile=perfil)
        db.commit()

        ui.resultado_tool(f"nmap · {perfil}", res.status, res.output, _pie_tool(res))

        if "1 host up" in (res.output or "") or "0 responded" in (res.output or ""):
            ui.advertencia("No se encontraron otros hosts. Posible AP Isolation.")
            ui.nota("Probá con el perfil [3] Profundo o [5] Enriquecido.")
        _pausar()
        return


def _submenu_capa2(db: Session, caso: Caso, target: str, herramienta: str, runner) -> None:
    while True:
        op = ui.menu(
            herramienta,
            [
                ("1", "Básico", "escaneo Capa 2"),
                ("2", "Enriquecido", "escaneo + IA para identificar dispositivos"),
                ("3", "Volver"),
            ],
        )
        if op == "3":
            return
        if op not in ["1", "2"]:
            ui.advertencia("Opción inválida.")
            continue
        if op == "2":
            _ejecutar_enriquecido(db, caso, target, herramienta)
            _pausar()
            return

        with ui.spinner(f"Ejecutando {herramienta} en {target}..."):
            res = runner(db, caso_id=caso.id, username=caso.creado_por, target=target)
        db.commit()
        ui.resultado_tool(herramienta, res.status, res.output, _pie_tool(res))
        _pausar()
        return


def _menu_deteccion_hosts(db: Session, caso: Caso) -> None:
    ip_local = _get_local_ip()
    target = "127.0.0.1" if ip_local.startswith("127.") else f"{'.'.join(ip_local.split('.')[:3])}.0/24"

    while True:
        op = ui.menu(
            "DETECCIÓN DE HOSTS EN RED LOCAL",
            [
                ("1", "nmap"),
                ("2", "arp-scan"),
                ("3", "netdiscover"),
                ("4", "Volver al menú principal"),
            ],
            subtitulo=f"Tu IP: {ip_local}   ·   Red detectada: {target}",
        )

        if op == "4":
            return
        elif op == "1":
            _menu_nmap_redes(db, caso, target)
        elif op == "2":
            _submenu_capa2(db, caso, target, "arp-scan", tools_service.run_arp_scan)
        elif op == "3":
            _submenu_capa2(db, caso, target, "netdiscover", tools_service.run_netdiscover)
        else:
            ui.advertencia("Opción no válida.")


# ─────────────────────────────────────────────
# Objetivos (Escaneo y IA Automática)
# ─────────────────────────────────────────────

_PERFILES_OBJETIVO = {
    "1": ("obj_default", "-sV -sC --top-ports 1000", "Balance estándar"),
    "2": ("obj_rapido", "-sV -F", "Top puertos, rápido"),
    "3": ("obj_completo", "-sV -sC -p-", "Los 65535 puertos (lento)"),
}


def _menu_objetivos(db: Session, caso: Caso) -> None:
    target = ui.pedir("IP o dominio del objetivo", obligatorio=False)
    if not target:
        return

    perfil_codigo = ui.menu(
        "nmap · Objetivos (Puertos/Servicios)",
        [(k, nombre, f"{flags}  —  {desc}") for k, (nombre, flags, desc) in _PERFILES_OBJETIVO.items()],
        prompt="Perfil",
    )
    perfil = _PERFILES_OBJETIVO.get(perfil_codigo, _PERFILES_OBJETIVO["1"])

    try:
        with ui.spinner(f"Ejecutando nmap ({perfil[0]}) contra {target}..."):
            res = tools_service.run_nmap(db, caso_id=caso.id, username=caso.creado_por, target=target, profile=perfil[0])
        db.commit()

        if res.status == "ok":
            cuerpo = res.output[:5000] if len(res.output or "") > 5000 else (res.output or "")
            ui.resultado_tool(f"nmap · {perfil[0]}", res.status, cuerpo, _pie_tool(res))
            _analizar_con_ia(db, caso, target, res)
        else:
            ui.resultado_tool(f"nmap · {perfil[0]}", res.status, res.output or "", _pie_tool(res))
    except Exception as exc:
        ui.error(f"Error al ejecutar nmap: {exc}")


def _analizar_con_ia(db: Session, caso: Caso, target: str, resultado_tool) -> None:
    from app.services import analisis_ia_service

    try:
        with ui.spinner("Enviando evidencia al modelo (Ollama + NVD), puede tardar..."):
            hallazgos = analisis_ia_service.analizar_evidencia(
                db, caso_id=caso.id, username=caso.creado_por,
                herramienta=resultado_tool.tool, resultado_tool=resultado_tool
            )
        db.commit()
    except ConnectionError as exc:
        ui.error("Error de conexión con Ollama:")
        ui.nota(str(exc))
        return
    except SQLAlchemyError as exc:
        ui.error("Error en la base de datos:")
        ui.nota(str(exc))
        return
    except Exception as exc:
        ui.error("Error inesperado en el análisis IA:")
        ui.nota(str(exc))
        return

    if not hallazgos:
        ui.info("No se registraron hallazgos validados.")
        _mostrar_riesgo_global(db, caso)
        return

    ui.titulo("SHARUR — ANÁLISIS DE VULNERABILIDADES", f"Target: {target}")
    for i, h in enumerate(hallazgos, 1):
        conf = h.confianza.value
        icono = ui.ICONO_CONFIANZA.get(conf, "[?]")
        lineas = [
            f"TÍTULO: {h.titulo}",
            f"SEVERIDAD: {h.severidad.value.upper()}",
        ]
        if h.cve_id:
            nvd = f" [Validado NVD · CVSS: {h.nvd_score}]" if h.nvd_verificado else " [No verificado]"
            lineas.append(f"CVE: {h.cve_id}{nvd}")
        lineas.append(f'CITA DE EVIDENCIA: "{h.cita_evidencia[:100]}..."')
        estilo = ui.COLOR_CONFIANZA.get(conf, ui.INFO)
        ui.panel("\n".join(lineas), cabecera=f"HALLAZGO {i}  ·  {icono} {conf.upper()}", estilo=estilo)

    confirmados = sum(1 for h in hallazgos if h.confianza.value == "confirmada")
    probables = sum(1 for h in hallazgos if h.confianza.value == "probable")
    descartados = sum(1 for h in hallazgos if h.confianza.value == "descartada")
    ui.info(f"{confirmados} validados por NVD   |   {probables} probables   |   {descartados} descartados")
    _mostrar_riesgo_global(db, caso)


def _mostrar_riesgo_global(db: Session, caso: Caso) -> None:
    """Nivel de riesgo del caso, calculado sobre TODOS los hallazgos registrados."""
    from app.models.hallazgo import Hallazgo
    from app.services.riesgo_service import nivel_riesgo_global

    hallazgos = db.query(Hallazgo).filter(Hallazgo.caso_id == caso.id).all()
    nivel = nivel_riesgo_global(hallazgos)
    ui.etiqueta_riesgo(nivel.value)


# ─────────────────────────────────────────────
# Menú principal del caso
# ─────────────────────────────────────────────

def menu_analisis(db: Session, caso: Caso) -> None:
    while True:
        opcion = ui.menu(
            f"SHARUR — Caso #{caso.id}",
            [
                ("1", "Detectar hosts en red local"),
                ("2", "Objetivos", "escaneo profundo + análisis IA"),
                ("3", "Consola libre"),
                ("4", "Ver auditoría del caso"),
                ("5", "Exportar informe del caso"),
                ("6", "Salir", "cierra el caso"),
            ],
            subtitulo=caso.numero_causa,
        )

        if opcion == "1":
            _menu_deteccion_hosts(db, caso)
        elif opcion == "2":
            _menu_objetivos(db, caso)
            _pausar()
        elif opcion == "3":
            _consola_libre(db, caso)
        elif opcion == "4":
            _mostrar_auditoria(db, caso)
            _pausar()
        elif opcion == "5":
            _exportar_informe(db, caso)
            _pausar()
        elif opcion == "6":
            return
        else:
            ui.advertencia("Opción no válida.")
