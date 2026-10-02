"""
Pruebas del criterio de aceptacion de RF-08 y RNF-01 (catalogo AE2).

RF-08  El sistema registra cada evento en una cadena de auditoria con hash
       encadenado: el hash de cada evento se calcula sobre sus campos mas el
       hash del evento anterior del mismo caso; el primero tiene hash previo nulo.

RNF-01 La auditoria es inalterable en sentido tamper-evident: toda modificacion
       de un registro pasado queda detectable al recalcular la cadena.

Estas pruebas se ejecutan sobre la funcion pura de calculo de hash, por lo que
no requieren base de datos.
"""

from app.services.auditoria_service import _calcular_hash_evento


def _evento(secuencia, descripcion="Caso creado", hash_anterior=None):
    return _calcular_hash_evento(
        secuencia=secuencia,
        tipo_evento="CASO_CREADO",
        actor_username="operador_prueba",
        descripcion=descripcion,
        detalle_json=None,
        timestamp_iso="2026-09-30T19:00:00",
        hash_evento_anterior=hash_anterior,
    )


def test_hash_es_sha256_hexadecimal():
    """El hash producido tiene la forma de un SHA-256 en hexadecimal."""
    h = _evento(1)
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_mismo_evento_produce_mismo_hash():
    """El calculo es determinista: los mismos campos dan el mismo hash."""
    assert _evento(1) == _evento(1)


def test_el_hash_depende_del_hash_anterior():
    """RF-08: dos eventos identicos encadenados a distinto antecesor difieren."""
    primero = _evento(1)
    encadenado = _evento(2, hash_anterior=primero)
    suelto = _evento(2, hash_anterior=None)
    assert encadenado != suelto


def test_alterar_un_campo_rompe_el_hash():
    """RNF-01: modificar la descripcion de un evento cambia su hash."""
    original = _evento(1, descripcion="Caso creado")
    alterado = _evento(1, descripcion="Caso creado (modificado)")
    assert original != alterado


def test_alteracion_pasada_invalida_la_cadena_posterior():
    """
    RNF-01, caso completo: una cadena de tres eventos donde se altera el
    primero deja de validar en el punto exacto de la ruptura.
    """
    e1 = _evento(1, descripcion="Caso creado")
    e2 = _evento(2, descripcion="Accion rechazada", hash_anterior=e1)
    e3 = _evento(3, descripcion="Caso cerrado", hash_anterior=e2)

    # Se altera el primer evento ya registrado.
    e1_alterado = _evento(1, descripcion="Caso creado (alterado)")

    # Al recalcular hacia adelante, la cadena ya no reproduce los hashes guardados.
    e2_recalculado = _evento(2, descripcion="Accion rechazada", hash_anterior=e1_alterado)
    assert e2_recalculado != e2

    e3_recalculado = _evento(3, descripcion="Caso cerrado", hash_anterior=e2_recalculado)
    assert e3_recalculado != e3
