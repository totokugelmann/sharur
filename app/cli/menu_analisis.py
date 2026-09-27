"""
Sharur SAIC - app/cli/menu_analisis.py

Menú principal de análisis. Todo por consola estándar (print/input).
Sin capa de UI.

Estructura:
  [1] Redes       → nmap (descubrimiento de hosts en un rango)
  [2] Objetivos   → nmap (puertos y servicios de un target)
  [3] Consola libre
  [4] Ver auditoría del caso
  [5] Salir (cierra el caso)

MVP: nmap, consola libre y el módulo de IA (analisis_ia_service con
Ollama + NVD) quedan como puntos de integración marcados. Se activan
cuando tools_service y consola_service se adapten a la firma del MVP
(sin orden ni dispositivo).

Todo lo que se ejecute queda firmado en la cadena de auditoría por
intermedio de auditoria_service (hash encadenado por caso).
"""

from sqlalchemy.orm import Session

from app.models.caso import Caso


def _prompt(msg: str, default: str = None) -> str:
    sufijo = f" [{default}]" if default else ""
    valor = input(f"{msg}{sufijo}: ").strip()
    return valor or default or ""


def _pausar() -> None:
    input("\nPresione ENTER para continuar...")


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
# nmap — categoría Redes (descubrimiento)
# ─────────────────────────────────────────────

_PERFILES_RED = {
    "1": ("descubrimiento", "-sn",                "Ping scan — sólo descubre hosts vivos"),
    "2": ("top_puertos",    "-sV --top-ports 100","Top 100 puertos con detección de versión"),
    "3": ("completo",       "-sV -p-",            "Los 65535 puertos con detección de versión"),
}


def _nmap_redes(db: Session, caso: Caso) -> None:
    print()
    print("--- nmap · Redes ---")
    target = _prompt("Rango o CIDR (ej: 192.168.1.0/24)")
    if not target:
        print("[!] Target vacío.")
        return
    print("Perfiles disponibles:")
    for k, (nombre, flags, desc) in _PERFILES_RED.items():
        print(f"  [{k}] {nombre:<16} {flags:<22} {desc}")
    perfil_codigo = _prompt("Perfil", default="1")
    perfil = _PERFILES_RED.get(perfil_codigo)
    if not perfil:
        print("[!] Perfil inválido.")
        return
    _ejecutar_nmap(db, caso, target, perfil[0], perfil[1], categoria="redes")


# ─────────────────────────────────────────────
# nmap — categoría Objetivos (puertos/servicios)
# ─────────────────────────────────────────────

_PERFILES_OBJETIVO = {
    "1": ("default",  "-sV -sC --top-ports 1000", "Balance estándar"),
    "2": ("rapido",   "-sV -F",                   "Top puertos, rápido"),
    "3": ("completo", "-sV -sC -p-",              "Los 65535 puertos (lento)"),
    "4": ("sigiloso", "-sS -T2",                  "SYN scan lento, menos detectable (requiere privilegios)"),
}


def _nmap_objetivos(db: Session, caso: Caso) -> None:
    print()
    print("--- nmap · Objetivos ---")
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
    _ejecutar_nmap(db, caso, target, perfil[0], perfil[1], categoria="objetivos")


# ─────────────────────────────────────────────
# Punto de integración con tools_service
# ─────────────────────────────────────────────

def _ejecutar_nmap(db: Session, caso: Caso, target: str,
                   perfil_nombre: str, perfil_flags: str, categoria: str) -> None:
    """
    Punto de integración con tools_service.
    En el MVP todavía NO se invoca: tools_service.run_nmap requiere
    dispositivo_id, y en este flujo todavía no se cargan dispositivos.
    Cuando adaptemos tools_service a la firma del MVP, aquí va la llamada:

        resultado = tools_service.run_nmap(
            db, caso_id=caso.id, dispositivo_id=None,
            username=caso.creado_por, target=target, profile=perfil_nombre,
        )
        db.commit()
        _mostrar_resultado(resultado)
    """
    print()
    print("[i] Escaneo solicitado:")
    print(f"    categoría : {categoria}")
    print(f"    target    : {target}")
    print(f"    perfil    : {perfil_nombre} ({perfil_flags})")
    print()
    print("[!] Pendiente: integrar tools_service.run_nmap (sin dispositivo).")
    print("    Cuando esté cableado, la salida se firmará con SHA-256 y")
    print("    se registrará como evidencia en la cadena de auditoría.")
    _ofrecer_analisis_ia(caso, target, categoria)


def _ofrecer_analisis_ia(caso: Caso, target: str, categoria: str) -> None:
    """
    Módulo IA (analisis_ia_service). En el MVP todavía no está cableado.
    Cuando se active:
      - corre en paralelo a la consola consumiendo el stdout de cada herramienta
      - consulta el LLM local (Ollama + sharur-qwen, ver Modelfile)
      - verifica cada CVE sugerida contra NVD (cve_search_service)
      - registra hallazgos verificados en la cadena de auditoría con hash

    Nota de diseño (evidence-first): el LLM propone, NVD valida, el operador
    acepta. Ningún hallazgo se firma sin pasar por NVD. Esto es no-negociable
    para que el hallazgo sea defendible como prueba.
    """
    print()
    print("[i] Análisis IA (Ollama + NVD): pendiente de integración en el MVP.")
    print("    Cuando se active, esta evidencia se enviará al LLM local y los")
    print("    CVEs sugeridos se verificarán contra NVD antes de firmarse.")


# ─────────────────────────────────────────────
# Consola libre
# ─────────────────────────────────────────────

def _consola_libre(db: Session, caso: Caso) -> None:
    """
    Punto de integración con consola_service. Cuando se active:
      - sólo permite binarios de la allow-list (config.py)
      - cada comando y su salida se firman con SHA-256
      - el resultado se envía al módulo IA en paralelo
    """
    print()
    print("[i] Consola libre: pendiente de integración (consola_service).")
    print("    Cuando se active, cada comando se validará contra la allow-list")
    print("    de binarios y quedará firmado en la cadena de auditoría.")


# ─────────────────────────────────────────────
# Menús
# ─────────────────────────────────────────────

def _menu_redes(db: Session, caso: Caso) -> None:
    while True:
        print()
        print("=" * 60)
        print("  REDES")
        print("=" * 60)
        print("  [1] nmap — descubrimiento de hosts")
        print("  [2] Volver")
        opcion = input("Opción: ").strip()
        if opcion == "1":
            _nmap_redes(db, caso)
            _pausar()
        elif opcion == "2":
            return
        else:
            print("[!] Opción no válida.")


def _menu_objetivos(db: Session, caso: Caso) -> None:
    while True:
        print()
        print("=" * 60)
        print("  OBJETIVOS")
        print("=" * 60)
        print("  [1] nmap — puertos y servicios")
        print("  [2] Volver")
        opcion = input("Opción: ").strip()
        if opcion == "1":
            _nmap_objetivos(db, caso)
            _pausar()
        elif opcion == "2":
            return
        else:
            print("[!] Opción no válida.")


def menu_analisis(db: Session, caso: Caso) -> None:
    while True:
        print()
        print("=" * 60)
        print(f"  SHARUR — Caso #{caso.id} ({caso.numero_causa})")
        print("=" * 60)
        print("  [1] Redes")
        print("  [2] Objetivos")
        print("  [3] Consola libre")
        print("  [4] Ver auditoría del caso")
        print("  [5] Salir (cierra el caso)")
        opcion = input("Opción: ").strip()

        if opcion == "1":
            _menu_redes(db, caso)
        elif opcion == "2":
            _menu_objetivos(db, caso)
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
