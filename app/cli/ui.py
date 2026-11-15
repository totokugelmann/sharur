"""
Sharur SAIC - app/cli/ui.py

Capa de presentacion de la consola, construida sobre `rich`.

Toda la interfaz del CLI pasa por aqui: banner, menus, paneles de
resultado, tablas de auditoria, prompts y mensajes de estado. El
objetivo es que Sharur se vea prolijo en la terminal sin dejar de ser
una aplicacion de linea de comandos (sin servidor web ni GUI).

Degrada con elegancia: si `rich` no esta instalado o la salida no es
una terminal (tests, tuberias, redireccion a archivo), las funciones
caen a `print()` plano y el flujo sigue funcionando igual. Por eso el
resto de la app importa SIEMPRE desde este modulo y nunca usa `rich`
directamente.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple, Union

try:  # rich es la via normal; el fallback existe para no romper nunca el import
    from rich.align import Align
    from rich.box import HEAVY, ROUNDED, SIMPLE_HEAD
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text

    _RICH = True
    console = Console(highlight=False)
except Exception:  # pragma: no cover - entorno sin rich
    _RICH = False
    console = None


# ── Paleta de la marca ──────────────────────────────────────────────
MARCA = "bold cyan"
OK = "bold green"
WARN = "bold yellow"
ERR = "bold red"
INFO = "cyan"
MUTED = "grey62"
ACENTO = "magenta"

# Color por severidad / confianza / riesgo (para hallazgos e informes)
COLOR_SEVERIDAD = {
    "critica": "bold white on red",
    "alta": "bold red",
    "media": "bold yellow",
    "baja": "green",
    "informativa": "cyan",
}
COLOR_CONFIANZA = {
    "confirmada": "bold green",
    "probable": "yellow",
    "descartada": "dim strike",
}
COLOR_RIESGO = {
    "critico": "bold white on red",
    "alto": "bold red",
    "medio": "bold yellow",
    "bajo": "green",
    "sin_hallazgos": "dim",
}
ICONO_CONFIANZA = {"confirmada": "[OK]", "probable": "[~]", "descartada": "[x]"}


_BANNER = r"""
 ___  _  _   __   ____  _  _  ____
/ __)/ )( \ / _\ (  _ \/ )( \(  _ \
\__ \) __ (/    \ )   /) \/ ( )   /
(___/\_)(_/\_/\_/(__\_)\____/(__\_)
"""


# ── Primitivas de salida ────────────────────────────────────────────
def _plano(texto: str = "") -> None:
    print(texto)


def limpiar() -> None:
    """Limpia la pantalla (no-op si no hay terminal)."""
    if _RICH and console.is_terminal:
        console.clear()


def banner(version: str = "") -> None:
    """Portada de arranque: logo + identidad institucional."""
    if not _RICH:
        _plano("=" * 52)
        _plano("  SHARUR  ·  SAIC")
        _plano("  Secretaria de Apoyo a Investigaciones Complejas")
        if version:
            _plano(f"  {version}")
        _plano("=" * 52)
        return

    logo = Text(_BANNER, style=MARCA)
    sub = Text("\nSecretaria de Apoyo a Investigaciones Complejas", style=MUTED)
    linea = Text("Adquisicion de evidencia · Analisis de red forense", style=INFO)
    pie = Text(version, style=f"dim {ACENTO}") if version else Text("")
    cuerpo = Group(Align.center(logo), Align.center(linea), Align.center(sub), Align.center(pie))
    console.print(Panel(cuerpo, box=HEAVY, border_style=MARCA, padding=(1, 4)))


def titulo(texto: str, subtitulo: str = "") -> None:
    """Encabezado de una pantalla."""
    if not _RICH:
        _plano("\n" + "=" * 60)
        _plano(f"  {texto}")
        if subtitulo:
            _plano(f"  {subtitulo}")
        _plano("=" * 60)
        return
    t = Text(texto, style=MARCA)
    if subtitulo:
        t.append(f"\n{subtitulo}", style=MUTED)
    console.print(Panel(t, box=ROUNDED, border_style=MARCA, padding=(0, 2)))


def subtitulo(texto: str) -> None:
    if not _RICH:
        _plano(f"\n  --- {texto} ---")
        return
    console.print(Rule(Text(texto, style=INFO), style=MUTED))


def _msg(prefijo: str, texto: str, estilo: str) -> None:
    if not _RICH:
        _plano(f"  {prefijo} {texto}")
        return
    console.print(Text(f"  {prefijo} ", style=estilo), Text(texto), sep="")


def info(texto: str) -> None:
    _msg("[i]", texto, INFO)


def exito(texto: str) -> None:
    _msg("[+]", texto, OK)


def advertencia(texto: str) -> None:
    _msg("[!]", texto, WARN)


def error(texto: str) -> None:
    _msg("[x]", texto, ERR)


def nota(texto: str) -> None:
    """Linea secundaria, atenuada."""
    if not _RICH:
        _plano(f"      {texto}")
        return
    console.print(Text(f"      {texto}", style=MUTED))


# ── Menus ───────────────────────────────────────────────────────────
Opcion = Union[Tuple[str, str], Tuple[str, str, str]]


def menu(
    cabecera: str,
    opciones: Sequence[Opcion],
    *,
    subtitulo: str = "",
    prompt: str = "Opcion",
) -> str:
    """
    Dibuja un menu y devuelve la tecla elegida (string, sin validar).

    `opciones` es una lista de (tecla, etiqueta) o (tecla, etiqueta, ayuda).
    """
    if not _RICH:
        _plano("\n" + "=" * 60)
        _plano(f"  {cabecera}")
        if subtitulo:
            _plano(f"  {subtitulo}")
        _plano("=" * 60)
        for op in opciones:
            tecla, etiqueta = op[0], op[1]
            ayuda = op[2] if len(op) > 2 else ""
            _plano(f"  [{tecla}] {etiqueta}" + (f"  — {ayuda}" if ayuda else ""))
        return input(f"\n{prompt}: ").strip()

    tabla = Table(box=None, show_header=False, padding=(0, 1), expand=False)
    tabla.add_column(justify="right", style=f"bold {ACENTO}", no_wrap=True)
    tabla.add_column(style="bold")
    tabla.add_column(style=MUTED)
    for op in opciones:
        tecla, etiqueta = op[0], op[1]
        ayuda = op[2] if len(op) > 2 else ""
        tabla.add_row(f"[{tecla}]", etiqueta, ayuda)

    titulo_panel = Text(cabecera, style=MARCA)
    if subtitulo:
        titulo_panel.append(f"\n{subtitulo}", style=MUTED)
    console.print(Panel(Group(titulo_panel, Text(""), tabla), box=ROUNDED, border_style=MARCA, padding=(1, 2)))
    return Prompt.ask(Text(prompt, style=INFO)).strip()


# ── Prompts ─────────────────────────────────────────────────────────
def pedir(mensaje: str, default: Optional[str] = None, obligatorio: bool = True) -> str:
    """
    Lee una linea. Si es obligatorio y viene vacio, vuelve a pedir.
    Un EOF (Ctrl+D o stdin agotado) se propaga para que el CLI cierre limpio.
    """
    while True:
        if _RICH:
            if default:
                valor = Prompt.ask(Text(mensaje, style=INFO), default=default).strip()
            else:
                valor = Prompt.ask(Text(mensaje, style=INFO)).strip()
        else:
            sufijo = f" [{default}]" if default else ""
            valor = input(f"{mensaje}{sufijo}: ").strip() or (default or "")
        if valor or not obligatorio:
            return valor
        advertencia("Este campo es obligatorio.")


def confirmar(mensaje: str, default: bool = False) -> bool:
    """Confirmacion sí/no que acepta español (s, si, sí) e inglés (y, yes)."""
    sufijo = "[S/n]" if default else "[s/n]"
    while True:
        try:
            if _RICH:
                resp = console.input(Text(f"{mensaje} {sufijo} ", style=INFO)).strip().lower()
            else:
                resp = input(f"{mensaje} {sufijo} ").strip().lower()
        except EOFError:
            return default
        if not resp:
            return default
        if resp in ("s", "si", "sí", "y", "yes"):
            return True
        if resp in ("n", "no"):
            return False
        advertencia("Respondé s (sí) o n (no).")


def pausar(mensaje: str = "Presione ENTER para continuar...") -> None:
    if _RICH:
        try:
            console.input(Text(f"\n{mensaje}", style=MUTED))
        except EOFError:
            pass
        return
    try:
        input(f"\n{mensaje}")
    except EOFError:
        pass


# ── Bloques de contenido ────────────────────────────────────────────
def panel(cuerpo: str, cabecera: str = "", estilo: str = INFO) -> None:
    if not _RICH:
        if cabecera:
            _plano("\n" + "=" * 60)
            _plano(f"  {cabecera}")
            _plano("=" * 60)
        _plano(cuerpo)
        return
    console.print(
        Panel(
            Text(cuerpo) if isinstance(cuerpo, str) else cuerpo,
            title=Text(cabecera, style=estilo) if cabecera else None,
            title_align="left",
            box=ROUNDED,
            border_style=estilo,
            padding=(1, 2),
        )
    )


def resultado_tool(cabecera: str, status: str, cuerpo: str, pie: str = "") -> None:
    """Panel para la salida de una herramienta (nmap, arp-scan, etc.)."""
    estilo = OK if status == "ok" else (WARN if status in ("timeout", "error") else ERR)
    if not _RICH:
        _plano("\n" + "=" * 60)
        _plano(f"  {cabecera}  ({status})")
        _plano("=" * 60)
        _plano(cuerpo or "(sin salida)")
        if pie:
            _plano(f"  {pie}")
        return
    grupo = Group(
        Text(cuerpo or "(sin salida)"),
        *( [Text(""), Text(pie, style=MUTED)] if pie else [] ),
    )
    console.print(
        Panel(
            grupo,
            title=Text(f"{cabecera}  ·  {status}", style=estilo),
            title_align="left",
            box=ROUNDED,
            border_style=estilo,
            padding=(1, 2),
        )
    )


def tabla_auditoria(eventos: Sequence) -> None:
    """Tabla de los ultimos eventos de la cadena de auditoria."""
    if not _RICH:
        for e in eventos:
            actor = e.actor_username or "-"
            _plano(f"  [{e.secuencia:04d}] {e.tipo_evento.value:<22} {actor:<15} {e.descripcion[:60]}")
        return
    t = Table(box=SIMPLE_HEAD, header_style=MARCA, expand=True, padding=(0, 1))
    t.add_column("#", justify="right", style=ACENTO, no_wrap=True)
    t.add_column("Evento", style="bold")
    t.add_column("Actor", style=INFO)
    t.add_column("Descripcion", style=MUTED, overflow="fold")
    for e in eventos:
        t.add_row(
            f"{e.secuencia:04d}",
            e.tipo_evento.value,
            e.actor_username or "-",
            (e.descripcion or "")[:80],
        )
    console.print(t)


def etiqueta_riesgo(nivel: str) -> None:
    estilo = COLOR_RIESGO.get(nivel, INFO)
    txt = nivel.replace("_", " ").upper()
    if not _RICH:
        _plano(f"  [RIESGO GLOBAL DEL CASO] {txt}")
        return
    console.print(Text("  RIESGO GLOBAL DEL CASO  ", style=MUTED), Text(f" {txt} ", style=estilo), sep="")


def spinner(mensaje: str):
    """
    Context manager para operaciones lentas (IA, NVD, escaneos largos).

    Uso:
        with ui.spinner("Consultando a la IA..."):
            ...trabajo...

    Si no hay terminal interactiva, imprime el mensaje una vez y no anima.
    """
    if _RICH and console.is_terminal:
        return console.status(Text(mensaje, style=INFO), spinner="dots")

    class _NoSpin:
        def __enter__(self_inner):
            info(mensaje)
            return self_inner

        def __exit__(self_inner, *a):
            return False

    return _NoSpin()
