"""
Sharur SAIC - app/cli/menu_analisis.py

Menú principal de análisis. Todo por consola estándar (print/input).
Sin capa de UI.

Estructura:
  [1] Detectar hosts en Red Local (nmap, arp-scan, netdiscover)
  [2] Objetivos (Escanear puertos/servicios)
  [3] Consola libre
  [4] Ver auditoría del caso
  [5] Salir (cierra el caso)
"""

import socket
from sqlalchemy.orm import Session

from app.models.caso import Caso
from app.services import tools_service


def _prompt(msg: str, default: str = None) -> str:
    sufijo = f" [{default}]" if default else ""
    valor = input(f"{msg}{sufijo}: ").strip()
    return valor or default or ""


def _pausar() -> None:
    input("\nPresione ENTER para continuar...")


def _get_local_ip() -> str:
    """Obtiene la IP local de la máquina (la que usa para salir a internet)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No se conecta realmente, solo le pide al SO que elija la interfaz
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


# ─────────────────────────────────────────────
# Auditoría
# ─────────────────────────────────────────────

def _mostrar_auditoria(db: Session, caso: Caso) -> None:
    from app.models.auditoria import EventoAuditoria

    eventos = (
        db.query(EventoAuditoria)
        .filter(EventoAuditoria.caso_id == caso.id)
        .order_by(EventoAuditoria.secuencia.desc())
        .limit(25)
        .all()
    )
    print()
    print("=" * 60)
    print(f"  ÚLTIMOS 25 EVENTOS DE AUDITORÍA — Caso #{caso.id}")
    print("=" * 60)
    if not eventos:
        print("  (sin eventos)")
        return
    for e in eventos:
        actor = e.actor_username or "-"
        print(f"  [{e.secuencia:04d}] {e.tipo_evento.value:<22} {actor:<15} {e.descripcion[:60]}")


# ─────────────────────────────────────────────
# Detección de Red Local (Descubrimiento)
# ─────────────────────────────────────────────

def _menu_deteccion_hosts(db: Session, caso: Caso) -> None:
    ip_local = _get_local_ip()
    
    if ip_local.startswith("127."):
        target = "127.0.0.1"
    else:
        # Toma la IP y le pone /24 (ej: 192.168.1.0/24)
        base_ip = ".".join(ip_local.split(".")[:3])
        target = f"{base_ip}.0/24"

    while True:
        print()
        print("=" * 60)
        print("  DETECCIÓN DE HOSTS EN RED LOCAL")
        print("=" * 60)
        print(f"  Tu IP: {ip_local} | Red detectada: {target}")
        print("  Seleccioná la herramienta de descubrimiento:")
        print("  [1] nmap (-sn)        — Ping scan estándar")
        print("  [2] arp-scan          — Rápido, obtiene MAC y Fabricante")
        print("  [3] netdiscover       — Pasivo/Activo, sin hacer ruido")
        print("  [4] Volver al menú principal")
        
        opcion = input("\nOpción: ").strip()

        if opcion == "4":
            return

        if opcion not in ["1", "2", "3"]:
            print("[!] Opción no válida.")
            continue

        herramienta = ""
        print(f"\n[*] Ejecutando detección con {opcion} en {target}...")
	print("    Esto puede tardar unos segundos...")

        try:
            if opcion == "1":
                herramienta = "nmap"
                resultado = tools_service.run_nmap(
                    db, caso_id=caso.id, username=caso.creado_por, 
                    target=target, profile="red_descubrimiento"
                )
            elif opcion == "2":
                herramienta = "arp-scan"
                resultado = tools_service.run_arp_scan(
                    db, caso_id=caso.id, username=caso.creado_por, target=target
                )
            elif opcion == "3":
                herramienta = "netdiscover"
                resultado = tools_service.run_netdiscover(
                    db, caso_id=caso.id, username=caso.creado_por, target=target
                )
            
            db.commit()

            print()
            print("=" * 60)
            print(f"  RESULTADO: {herramienta} ({resultado.status})")
            print("=" * 60)
            
            if resultado.status == "not_found":
                print(f"[!] {resultado.stderr}")
                print("[!] Asegurate de tener instalada la herramienta y ejecutar el CLI con 'sudo'.")
            elif resultado.status == "error":
                print(f"[!] Error al ejecutar: {resultado.stderr}")
                if "root" in resultado.stderr.lower() or "permiso" in resultado.stderr.lower():
                    print("[!] TIP: Ejecutá 'sudo python sharur_cli.py' para obtener permisos.")
            else:
                print(resultado.output or "(sin salida)")
                print(f"\n[i] Duración: {resultado.duration_seconds:.2f}s")
                print(f"[i] Hash de evidencia: {resultado.evidence_hash[:16]}...")
                print("\n[i] TIP: Copiá la IP de alguno de los dispositivos de arriba")
                print("    y usala en la opción [2] Objetivos para escanear sus puertos.")

        except Exception as exc:
            print(f"\n[!] Error inesperado: {exc}")

        _pausar()


# ─────────────────────────────────────────────
# Objetivos (Escaneo de puertos/servicios)
# ─────────────────────────────────────────────

_PERFILES_OBJETIVO = {
    "1": ("obj_default",  "-sV -sC --top-ports 1000", "Balance estándar"),
    "2": ("obj_rapido",   "-sV -F",                   "Top puertos, rápido"),
    "3": ("obj_completo", "-sV -sC -p-",              "Los 65535 puertos (lento)"),
    "4": ("obj_sigiloso", "-sS -T2",                  "SYN scan lento, menos detectable (requiere privilegios)"),
}

def _menu_objetivos(db: Session, caso: Caso) -> None:
    print()
    print("--- nmap · Objetivos (Puertos/Servicios) ---")
    target = _prompt("IP o dominio del objetivo")
    if not target:
        print("[!] Target vacío.")
        return
    print("Perfiles disponibles:")
    for k, (nombre, flags, desc) in _PERFILES_OBJETIVO.items():
        print(f"  [{k}] {nombre:<10} {flags:<27} {desc}")
    perfil_codigo = _prompt("Perfil", default="1")
    perfil = _PERFILES_OBJETIVO.get(perfil_codigo)
    if not perfil:
        print("[!] Perfil inválido.")
        return
    _ejecutar_nmap_objetivo(db, caso, target, perfil[0], perfil[1])


def _ejecutar_nmap_objetivo(db: Session, caso: Caso, target: str, perfil_nombre: str, perfil_flags: str) -> None:
    print()
    print(f"[*] Ejecutando nmap (perfil: {perfil_nombre}) contra {target}...")
    try:
        resultado = tools_service.run_nmap(
            db, caso_id=caso.id, username=caso.creado_por, target=target, profile=perfil_nombre,
        )
        db.commit()

        print()
        print("=" * 60)
        print(f"  RESULTADO: nmap ({resultado.status})")
        print("=" * 60)
        if resultado.status == "not_found":
            print(f"[!] {resultado.stderr}")
            return

        salida = resultado.output
        if len(salida) > 5000:
            print(salida[:5000])
            print(f"\n[... salida truncada. Total: {len(salida)} caracteres ...]")
        else:
            print(salida or "(sin salida)")

        if resultado.stderr:
            print(f"\n[!] stderr: {resultado.stderr[:500]}")

        print(f"\n[i] Duración: {resultado.duration_seconds:.2f}s")
        print(f"[i] Hash de evidencia: {resultado.evidence_hash[:16]}...")

        _ofrecer_analisis_ia(caso, target, "objetivos")

    except Exception as exc:
        print(f"\n[!] Error al ejecutar nmap: {exc}")


def _ofrecer_analisis_ia(caso: Caso, target: str, categoria: str) -> None:
    print()
    print("[i] Análisis IA (Ollama + NVD): pendiente de integración en el MVP.")
    print("    Cuando se active, esta evidencia se enviará al LLM local y los")
    print("    CVEs sugeridos se verificarán contra NVD antes de firmarse.")


# ─────────────────────────────────────────────
# Consola libre
# ─────────────────────────────────────────────

def _consola_libre(db: Session, caso: Caso) -> None:
    print()
    print("[i] Consola libre: pendiente de integración (consola_service).")
    print("    Cuando se active, cada comando se validará contra la allow-list")
    print("    de binarios y quedará firmado en la cadena de auditoría.")


# ─────────────────────────────────────────────
# Menú Principal
# ─────────────────────────────────────────────

def menu_analisis(db: Session, caso: Caso) -> None:
    while True:
        print()
        print("=" * 60)
        print(f"  SHARUR — Caso #{caso.id} ({caso.numero_causa})")
        print("=" * 60)
        print("  [1] Detectar hosts en Red Local")
        print("  [2] Objetivos (Escanear puertos/servicios)")
        print("  [3] Consola libre")
        print("  [4] Ver auditoría del caso")
        print("  [5] Salir (cierra el caso)")
        opcion = input("Opción: ").strip()

        if opcion == "1":
            _menu_deteccion_hosts(db, caso)
        elif opcion == "2":
            _menu_objetivos(db, caso)
            _pausar()
        elif opcion == "3":
            _consola_libre(db, caso)
            _pausar()
        elif opcion == "4":
            _mostrar_auditoria(db, caso)
            _pausar()
        elif opcion == "5":
            return
        else:
            print("[!] Opción no válida.")
