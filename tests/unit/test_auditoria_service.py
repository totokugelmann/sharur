"""
Sharur SAIC - tests/unit/test_auditoria_service.py

Tests del encadenado de hashes de auditoria: la propiedad
central es que alterar cualquier campo de un evento pasado debe
ser detectable por verificar_cadena().
"""

from app.models.auditoria import TipoEvento
from app.models.caso import Caso
from app.services.auditoria_service import registrar_evento, verificar_cadena


def _crear_caso(db_session):
    caso = Caso(
        numero_causa="CAUSA-002",
        caratula="Test auditoria",
        juzgado_interviniente="Juzgado 1",
        creado_por="tester",
    )
    db_session.add(caso)
    db_session.flush()
    return caso


def test_cadena_vacia_es_integra(db_session):
    caso = _crear_caso(db_session)
    resultado = verificar_cadena(db_session, caso.id)

    assert resultado["integra"] is True
    assert resultado["total_eventos"] == 0


def test_eventos_se_encadenan_correctamente(db_session):
    caso = _crear_caso(db_session)

    e1 = registrar_evento(db_session, caso.id, TipoEvento.CASO_CREADO, "Evento 1", actor_username="a")
    e2 = registrar_evento(db_session, caso.id, TipoEvento.ORDEN_CARGADA, "Evento 2", actor_username="a")

    assert e1.secuencia == 1
    assert e2.secuencia == 2
    assert e1.hash_evento_anterior is None
    assert e2.hash_evento_anterior == e1.hash_evento

    resultado = verificar_cadena(db_session, caso.id)
    assert resultado["integra"] is True
    assert resultado["total_eventos"] == 2


def test_detecta_alteracion_de_contenido_de_evento_pasado(db_session):
    caso = _crear_caso(db_session)

    registrar_evento(db_session, caso.id, TipoEvento.CASO_CREADO, "Evento original", actor_username="a")
    registrar_evento(db_session, caso.id, TipoEvento.ORDEN_CARGADA, "Evento 2", actor_username="a")
    db_session.commit()

    from app.models.auditoria import EventoAuditoria

    primero = db_session.query(EventoAuditoria).filter_by(secuencia=1).one()
    primero.descripcion = "Evento ALTERADO despues del hecho"
    db_session.flush()

    resultado = verificar_cadena(db_session, caso.id)

    assert resultado["integra"] is False
    assert resultado["primer_evento_alterado"] == 1


def test_detecta_ruptura_de_cadena_por_hash_anterior_incorrecto(db_session):
    caso = _crear_caso(db_session)

    registrar_evento(db_session, caso.id, TipoEvento.CASO_CREADO, "Evento 1", actor_username="a")
    registrar_evento(db_session, caso.id, TipoEvento.ORDEN_CARGADA, "Evento 2", actor_username="a")
    db_session.commit()

    from app.models.auditoria import EventoAuditoria

    segundo = db_session.query(EventoAuditoria).filter_by(secuencia=2).one()
    segundo.hash_evento_anterior = "0" * 64
    db_session.flush()

    resultado = verificar_cadena(db_session, caso.id)

    assert resultado["integra"] is False
    assert resultado["primer_evento_alterado"] == 2
