"""Que todos los modulos del CLI importen en una instalacion limpia."""

import importlib

import pytest

MODULOS = [
    "app.cli.ui",
    "app.cli.consola",
    "app.cli.menu_analisis",
    "app.cli.sesion",
    "app.schemas.auditoria",
    "app.services.analisis_ia_service",
    "app.services.cve_search_service",
    "app.services.llm_service",
    "app.services.riesgo_service",
    "app.services.reporte_service",
]


@pytest.mark.parametrize("modulo", MODULOS)
def test_importa(modulo):
    importlib.import_module(modulo)
