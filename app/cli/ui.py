"""
Sharur SAIC - app/cli/ui.py

Helpers minimos de salida por consola estandar (print). Sin dependencias.
"""


def titulo(texto: str) -> None:
    print("\n" + "=" * 60)
    print(f"  {texto}")
    print("=" * 60)


def subtitulo(texto: str) -> None:
    print(f"\n  --- {texto} ---")


def info(texto: str) -> None:
    print(f"  [i] {texto}")


def advertencia(texto: str) -> None:
    print(f"  [!] {texto}")


def error(texto: str) -> None:
    print(f"  [X] {texto}")
