"""Un caso cerrado es inmutable: no puede cerrarse de nuevo (validado en entrevista 25/09/2026)."""

from types import SimpleNamespace

import pytest

from app.models.caso import EstadoCaso
from app.services import caso_service


def test_no_se_puede_cerrar_un_caso_ya_cerrado():
    caso = SimpleNamespace(estado=EstadoCaso.CERRADO_MANUAL)
    with pytest.raises(ValueError):
        caso_service.cerrar_caso(None, caso, "otro motivo", "operador")
