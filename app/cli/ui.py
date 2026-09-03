
import sys
from typing import Callable, Optional


def clear_line() -> None:
    print()


def titulo(texto: str) -> None:
    print()
    print("=" * 70)
    print(f" {texto}")
    print("=" * 70)


def subtitulo(texto: str) -> None:
    print()
    print(f"── {texto} " + "─" * max(0, 60 - len(texto)))


def info(texto: str) -> None:
    print(f"  {texto}")


def ok(texto: str) -> None:
    print(f"  [OK] {texto}")


def advertencia(texto: str) -> None:
    print(f"  [!] {texto}")


def error(texto: str) -> None:
    print(f"  [ERROR] {texto}")


def prompt(mensaje: str, default: Optional[str] = None, requerido: bool = True) -> str:
    sufijo = f" [{default}]" if default else ""
    while True:
        valor = input(f"  {mensaje}{sufijo}: ").strip()
        if not valor and default is not None:
            return default
        if not valor and not requerido:
            return ""
        if valor:
            return valor
        print("    (este dato es obligatorio)")


def prompt_int(mensaje: str, default: Optional[int] = None) -> int:
    sufijo = f" [{default}]" if default is not None else ""
    while True:
        valor = input(f"  {mensaje}{sufijo}: ").strip()
        if not valor and default is not None:
            return default
        try:
            return int(valor)
        except ValueError:
            print("    (ingresá un número válido)")


def prompt_si_no(mensaje: str, default: bool = False) -> bool:
    sufijo = " [S/n]" if default else " [s/N]"
    valor = input(f"  {mensaje}{sufijo}: ").strip().lower()
    if not valor:
        return default
    return valor in ("s", "si", "sí", "y", "yes")


def menu(titulo_menu: str, opciones: "list[tuple[str, str]]") -> str:
    """
    Muestra un menu numerado. `opciones` es una lista de tuplas
    (codigo, etiqueta). El codigo es lo que devuelve la funcion
    cuando el usuario elige esa opcion; la numeracion visible en
    pantalla es automatica (1, 2, 3, ...), no hace falta que el
    codigo sea numerico.
    """
    subtitulo(titulo_menu)
    for i, (_, etiqueta) in enumerate(opciones, start=1):
        print(f"  {i}. {etiqueta}")
    print()

    codigos_validos = {str(i): codigo for i, (codigo, _) in enumerate(opciones, start=1)}

    while True:
        eleccion = input("  Elegí una opción: ").strip()
        if eleccion in codigos_validos:
            return codigos_validos[eleccion]
        print("    Opción inválida, probá de nuevo.")


def tabla(encabezados: "list[str]", filas: "list[list[str]]") -> None:
    if not filas:
        info("(sin resultados)")
        return

    anchos = [len(h) for h in encabezados]
    for fila in filas:
        for i, celda in enumerate(fila):
            anchos[i] = max(anchos[i], len(str(celda)))

    linea_encabezado = "  " + "  ".join(h.ljust(anchos[i]) for i, h in enumerate(encabezados))
    print(linea_encabezado)
    print("  " + "-" * (len(linea_encabezado) - 2))
    for fila in filas:
        print("  " + "  ".join(str(c).ljust(anchos[i]) for i, c in enumerate(fila)))


def pausar() -> None:
    input("\n  (Enter para continuar) ")


def confirmar_salida() -> bool:
    return prompt_si_no("¿Confirmás que querés salir?", default=False)
