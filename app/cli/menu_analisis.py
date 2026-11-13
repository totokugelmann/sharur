"""
Sharur SAIC - app/cli/menu_analisis.py

Menú principal de análisis.
- Redes: Descubrimiento de hosts (con opción de Enriquecimiento por IA).
- Objetivos: Escaneo profundo y análisis automático con IA.
"""

import socket
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.models.caso import Caso
from app.services import tools_service


def _prompt(msg: str, default: str = None) -> str:
    sufijo = f" [{default}]" if default else ""
    valor = input(f"{msg}{sufijo}: ").strip()
    return valor or default or ""


def _pausar() -> None:
    input("\nPresione ENTER para continuar...")


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


def _mostrar_auditoria(db: Session, caso: Caso) -> None:
    from app.models.auditoria import EventoAuditoria
    eventos = (
        db.query(EventoAuditoria)
        .filter(EventoAuditoria.caso_id == caso.id)
        .order_by(EventoAuditoria.secuencia.desc())
        .limit(25)
        .all()
    )
    print("\n" + "=" * 60)
    print(f"  ÚLTIMOS 25 EVENTOS DE AUDITORÍA — Caso #{caso.id}")
    print("=" * 60)
    if not eventos:
        print("  (sin eventos)")
        return
    for e in eventos:
        actor = e.actor_username or "-"
        print(f"  [{e.secuencia:04d}] {e.tipo_evento.value:<22} {actor:<15} {e.descripcion[:60]}")


# ─────────────────────────────────────────────
# Lógica de Escaneo Enriquecido (IA)
# ─────────────────────────────────────────────

def _ejecutar_enriquecido(db: Session, caso: Caso, target: str, herramienta_base: str) -> None:
    """Ejecuta la herramienta base, busca puertos clave y llama a la IA."""
    from app.services import analisis_ia_service

    print(f"\n[*] Fase 1: Ejecutando {herramienta_base} base...")
    res_base = None
    if herramienta_base == "arp-scan":
        res_base = tools_service.run_arp_scan(db, caso_id=caso.id, username=caso.creado_por, target=target)
    elif herramienta_base == "netdiscover":
        res_base = tools_service.run_netdiscover(db, caso_id=caso.id, username=caso.creado_por, target=target)
    elif herramienta_base == "nmap":
        res_base = tools_service.run_nmap(db, caso_id=caso.id, username=caso.creado_por, target=target, profile="red_basico")
    
    if not res_base or res_base.status != "ok":
        print("[!] Falló el escaneo base.")
        return

    print("[*] Fase 2: Buscando huellas de dispositivos (puertos clave)...")
    res_puertos = tools_service.run_nmap(
        db, caso_id=caso.id, username=caso.creado_por, target=target, profile="red_identificacion"
    )
    db.commit()

    print("[*] Fase 3: Enviando evidencia a la IA para identificar dispositivos...")
    print("    Esto puede tardar (la IA está analizando las MACs y puertos)...")

    try:
        dispositivos = analisis_ia_service.identificar_dispositivos_red(
            db, caso_id=caso.id, username=caso.creado_por,
            resultado_arp=res_base, resultado_nmap_puertos=res_puertos
        )
    except Exception as exc:
        print(f"\n[!] Error consultando a la IA: {exc}")
        return

    if not dispositivos:
        print("\n[i] La IA no pudo identificar dispositivos (o la red está vacía).")
        return

    print("\n" + "═" * 60)
    print("  INVENTARIO DE DISPOSITIVOS IDENTIFICADOS")
    print("═" * 60)
    for d in dispositivos:
        print(f"  IP: {d.get('ip')} | MAC: {d.get('mac')}")
        print(f"  TIPO: {d.get('tipo')} (Confianza: {d.get('confianza').upper()})")
        print(f"  RAZÓN: {d.get('razon')}")
        print("─" * 60)


# ─────────────────────────────────────────────
# Submenús de Redes
# ─────────────────────────────────────────────

def _menu_nmap_redes(db: Session, caso: Caso, target: str) -> None:
    while True:
        print("\n  --- Perfiles de Nmap (Redes) ---")
        print("  [1] Básico     (-sn) Ping scan estándar")
        print("  [2] Rápido     (-sn -T4 -n) Ping rápido sin DNS")
        print("  [3] Profundo   (-Pn -PS...) Fuerza TCP SYN, atraviesa firewalls")
        print("  [4] Sigiloso   (-sn -T2) Ping lento, menos ruido")
        print("  [5] Enriquecido (Escaneo + IA para identificar dispositivos)")
        print("  [6] Volver")
        
        op = input("  Opción: ").strip()
        
        if op == "6": return
        if op not in ["1", "2", "3", "4", "5"]:
            print("[!] Opción inválida.")
            continue

        if op == "5":
            _ejecutar_enriquecido(db, caso, target, "nmap")
            _pausar()
            return

        perfil = {"1": "red_basico", "2": "red_rapido", "3": "red_profundo", "4": "red_sigiloso"}[op]
        print(f"\n[*] Ejecutando nmap ({perfil}) en {target}...")
        res = tools_service.run_nmap(db, caso_id=caso.id, username=caso.creado_por, target=target, profile=perfil)
        db.commit()
        
        print("\n" + "=" * 60)
        print(f"  RESULTADO: nmap ({res.status})")
        print("=" * 60)
        print(res.output or "(sin salida)")
        print(f"\n[i] Duración: {res.duration_seconds:.2f}s | Hash: {res.evidence_hash[:16]}...")
        
        if "1 host up" in res.output or "0 responded" in res.output:
            print("\n[!] No se encontraron otros hosts. Posible AP Isolation.")
            print("    ==> PROBÁ CON EL PERFIL [3] PROFUNDO o [5] ENRIQUECIDO.")
        _pausar()
        return


def _menu_arp_scan(db: Session, caso: Caso, target: str) -> None:
    while True:
        print("\n  --- arp-scan ---")
        print("  [1] Básico     (Escaneo Capa 2 ultra rápido)")
        print("  [2] Enriquecido (Escaneo + IA para identificar dispositivos)")
        print("  [3] Volver")
        
        op = input("  Opción: ").strip()
        
        if op == "3": return
        if op not in ["1", "2"]:
            print("[!] Opción inválida.")
            continue

        if op == "2":
            _ejecutar_enriquecido(db, caso, target, "arp-scan")
            _pausar()
            return

        print(f"\n[*] Ejecutando arp-scan en {target}...")
        res = tools_service.run_arp_scan(db, caso_id=caso.id, username=caso.creado_por, target=target)
        db.commit()
        
        print("\n" + "=" * 60)
        print(f"  RESULTADO: arp-scan ({res.status})")
        print("=" * 60)
        print(res.output or "(sin salida)")
        print(f"\n[i] Duración: {res.duration_seconds:.2f}s | Hash: {res.evidence_hash[:16]}...")
        _pausar()
        return


def _menu_netdiscover(db: Session, caso: Caso, target: str) -> None:
    while True:
        print("\n  --- netdiscover ---")
        print("  [1] Básico     (Escaneo Capa 2)")
        print("  [2] Enriquecido (Escaneo + IA para identificar dispositivos)")
        print("  [3] Volver")
        
        op = input("  Opción: ").strip()
        
        if op == "3": return
        if op not in ["1", "2"]:
            print("[!] Opción inválida.")
            continue

        if op == "2":
            _ejecutar_enriquecido(db, caso, target, "netdiscover")
            _pausar()
            return

        print(f"\n[*] Ejecutando netdiscover en {target}...")
        res = tools_service.run_netdiscover(db, caso_id=caso.id, username=caso.creado_por, target=target)
        db.commit()
        
        print("\n" + "=" * 60)
        print(f"  RESULTADO: netdiscover ({res.status})")
        print("=" * 60)
        print(res.output or "(sin salida)")
        print(f"\n[i] Duración: {res.duration_seconds:.2f}s | Hash: {res.evidence_hash[:16]}...")
        _pausar()
        return


# ─────────────────────────────────────────────
# Menú Principal de Redes
# ─────────────────────────────────────────────

def _menu_deteccion_hosts(db: Session, caso: Caso) -> None:
    ip_local = _get_local_ip()
    target = "127.0.0.1" if ip_local.startswith("127.") else f"{'.'.join(ip_local.split('.')[:3])}.0/24"

    while True:
        print("\n" + "=" * 60)
        print("  DETECCIÓN DE HOSTS EN RED LOCAL")
        print("=" * 60)
        print(f"  Tu IP: {ip_local} | Red detectada: {target}")
        print("  Seleccioná la herramienta:")
        print("  [1] nmap")
        print("  [2] arp-scan")
        print("  [3] netdiscover")
        print("  [4] Volver al menú principal")
        
        op = input("\nOpción: ").strip()

        if op == "4": return
        elif op == "1": _menu_nmap_redes(db, caso, target)
        elif op == "2": _menu_arp_scan(db, caso, target)
        elif op == "3": _menu_netdiscover(db, caso, target)
        else: print("[!] Opción no válida.")


# ─────────────────────────────────────────────
# Objetivos (Escaneo y IA Automática)
# ─────────────────────────────────────────────

_PERFILES_OBJETIVO = {
    "1": ("obj_default",  "-sV -sC --top-ports 1000", "Balance estándar"),
    "2": ("obj_rapido",   "-sV -F",                   "Top puertos, rápido"),
    "3": ("obj_completo", "-sV -sC -p-",              "Los 65535 puertos (lento)"),
    "4": ("obj_sigiloso", "-sS -T2",                  "SYN scan lento (requiere privilegios)"),
}

def _menu_objetivos(db: Session, caso: Caso) -> None:
    print("\n--- nmap · Objetivos (Puertos/Servicios) ---")
    target = _prompt("IP o dominio del objetivo")
    if not target: return
    
    print("Perfiles disponibles:")
    for k, (nombre, flags, desc) in _PERFILES_OBJETIVO.items():
        print(f"  [{k}] {nombre:<10} {flags:<27} {desc}")
    perfil_codigo = _prompt("Perfil", default="1")
    perfil = _PERFILES_OBJETIVO.get(perfil_codigo, _PERFILES_OBJETIVO["1"])

    print(f"\n[*] Ejecutando nmap ({perfil[0]}) contra {target}...")
    try:
        res = tools_service.run_nmap(db, caso_id=caso.id, username=caso.creado_por, target=target, profile=perfil[0])
        db.commit()

        print("\n" + "=" * 60)
        print(f"  RESULTADO: nmap ({res.status})")
        print("=" * 60)
        
        if res.status == "ok":
            print(res.output[:5000] if len(res.output) > 5000 else res.output)
            print(f"\n[i] Duración: {res.duration_seconds:.2f}s | Hash: {res.evidence_hash[:16]}...")
            
            # LLAMADA AUTOMÁTICA A LA IA
            _analizar_con_ia(db, caso, target, res)

    except Exception as exc:
        print(f"\n[!] Error al ejecutar nmap: {exc}")


def _analizar_con_ia(db: Session, caso: Caso, target: str, resultado_tool) -> None:
    from app.services import analisis_ia_service
    
    print("\n[*] ENVIANDO EVIDENCIA AL MODELO DE IA (Ollama + NVD)...")
    print("    Analizando vulnerabilidades, puede tardar unos segundos...")

    try:
        hallazgos = analisis_ia_service.analizar_evidencia(
            db, caso_id=caso.id, username=caso.creado_por,
            herramienta=resultado_tool.tool, resultado_tool=resultado_tool
        )
        db.commit()
    except ConnectionError as exc:
        print(f"\n[!] ERROR DE CONEXIÓN CON OLLAMA:")
        print(f"    {exc}")
        print("    Asegurate de tener Ollama corriendo y con el modelo cargado.")
        return
    except SQLAlchemyError as exc:
        print(f"\n[!] ERROR EN LA BASE DE DATOS:")
        print(f"    No se pudieron guardar los hallazgos: {exc}")
        return
    except Exception as exc:
        print(f"\n[!] ERROR INESPERADO EN EL ANÁLISIS IA:")
        print(f"    {exc}")
        return

    if not hallazgos:
        print("\n[i] No se registraron hallazgos validados.")
        print("    (Puede que el modelo no haya encontrado nada, o que la respuesta se haya cortado).")
        return

    print("\n" + "═" * 60)
    print(f"  [SHARUR - ANÁLISIS DE VULNERABILIDADES]")
    print(f"  TARGET: {target}")
    print("═" * 60)
    
    for i, h in enumerate(hallazgos, 1):
        icono = "✓" if h.confianza.value == "confirmada" else ("~" if h.confianza.value == "probable" else "X")
        print(f"\nHALLAZGO {i} | {icono} CONFIANZA: {h.confianza.value.upper()}")
        print(f"├─ TÍTULO: {h.titulo}")
        print(f"├─ SEVERIDAD: {h.severidad.value.upper()}")
        if h.cve_id:
            nvd_info = f" [Validado NVD - CVSS: {h.nvd_score}]" if h.nvd_verificado else " [No verificado]"
            print(f"├─ CVE: {h.cve_id}{nvd_info}")
        print(f"├─ CITA DE EVIDENCIA: \"{h.cita_evidencia[:100]}...\"")
        print("─" * 60)

    print(f"\n[RESUMEN] Se procesaron {len(hallazgos)} hallazgos. Todo guardado en la auditoría.")


def _consola_libre(db: Session, caso: Caso) -> None:
    print("\n[i] Consola libre: pendiente de integración (consola_service).")


def menu_analisis(db: Session, caso: Caso) -> None:
    while True:
        print("\n" + "=" * 60)
        print(f"  SHARUR — Caso #{caso.id} ({caso.numero_causa})")
        print("=" * 60)
        print("  [1] Detectar hosts en Red Local")
        print("  [2] Objetivos (Escaneo profundo + Análisis IA)")
        print("  [3] Consola libre")
        print("  [4] Ver auditoría del caso")
        print("  [5] Salir (cierra el caso)")
        opcion = input("Opción: ").strip()

        if opcion == "1": _menu_deteccion_hosts(db, caso)
        elif opcion == "2": _menu_objetivos(db, caso); _pausar()
        elif opcion == "3": _consola_libre(db, caso); _pausar()
        elif opcion == "4": _mostrar_auditoria(db, caso); _pausar()
        elif opcion == "5": return
        else: print("[!] Opción no válida.")
