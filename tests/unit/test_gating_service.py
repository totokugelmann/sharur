"""
Sharur SAIC - tests/unit/test_gating_service.py

Tests del motor de gating: dispositivo / tiempo / operador.
Esta es la pieza que hace al sistema defendible como prueba, asi
que se testea cada motivo de rechazo por separado.
"""

from datetime import timedelta

from app.core.utils import utc_now
from app.models.caso import Caso
from app.models.dispositivo import Dispositivo, EstadoDispositivo, TipoDispositivo
from app.models.orden import EstadoOrden, Orden, PersonalAutorizado
from app.services.gating_service import MotivoRechazoGating, evaluar_gating


def _crear_caso_orden_dispositivo(
    db_session,
    vigente_desde=None,
    vigente_hasta=None,
    prorroga_hasta=None,
    estado_dispositivo=EstadoDispositivo.AUTORIZADO_ACTIVO,
    es_hallazgo_casual=False,
    hallazgo_casual_aprobado_por=None,
    estado_orden=EstadoOrden.VIGENTE,
):
    ahora = utc_now()
    caso = Caso(
        numero_causa="CAUSA-001",
        caratula="Test",
        juzgado_interviniente="Juzgado 1",
        creado_por="tester",
    )
    db_session.add(caso)
    db_session.flush()

    orden = Orden(
        caso_id=caso.id,
        numero_orden="ORD-001",
        juez_firmante="Juez Test",
        fecha_emision=ahora,
        vigente_desde=vigente_desde or (ahora - timedelta(days=1)),
        vigente_hasta=vigente_hasta or (ahora + timedelta(days=1)),
        prorroga_hasta=prorroga_hasta,
        fundamento_proporcionalidad="x" * 10,
        fundamento_necesidad="x" * 10,
        fundamento_idoneidad="x" * 10,
        imputado_identificacion="N.N.",
        estado=estado_orden,
    )
    db_session.add(orden)
    db_session.flush()

    dispositivo = Dispositivo(
        orden_id=orden.id,
        tipo=TipoDispositivo.HOST_RED,
        identificador="192.0.2.10",
        identificador_normalizado="192.0.2.10",
        sub_alcance_datos="servicios de red expuestos",
        estado=estado_dispositivo,
        es_hallazgo_casual=es_hallazgo_casual,
        hallazgo_casual_aprobado_por=hallazgo_casual_aprobado_por,
    )
    db_session.add(dispositivo)
    db_session.flush()

    return caso, orden, dispositivo


def _autorizar_operador(db_session, orden, username="operador1"):
    personal = PersonalAutorizado(
        orden_id=orden.id,
        username=username,
        nombre_completo="Operador Uno",
        rol_funcional="perito",
    )
    db_session.add(personal)
    db_session.flush()
    return personal


def test_accion_autorizada_cuando_todo_es_valido(db_session):
    caso, orden, dispositivo = _crear_caso_orden_dispositivo(db_session)
    _autorizar_operador(db_session, orden, "operador1")

    resultado = evaluar_gating(db_session, dispositivo_id=dispositivo.id, username="operador1")

    assert resultado.autorizado is True
    assert resultado.motivo_rechazo is None


def test_rechaza_dispositivo_inexistente(db_session):
    resultado = evaluar_gating(db_session, dispositivo_id=99999, username="operador1")

    assert resultado.autorizado is False
    assert resultado.motivo_rechazo == MotivoRechazoGating.DISPOSITIVO_NO_ENCONTRADO


def test_rechaza_dispositivo_excluido(db_session):
    _, orden, dispositivo = _crear_caso_orden_dispositivo(
        db_session, estado_dispositivo=EstadoDispositivo.EXCLUIDO
    )
    _autorizar_operador(db_session, orden, "operador1")

    resultado = evaluar_gating(db_session, dispositivo_id=dispositivo.id, username="operador1")

    assert resultado.autorizado is False
    assert resultado.motivo_rechazo == MotivoRechazoGating.DISPOSITIVO_EXCLUIDO


def test_rechaza_dispositivo_con_objetivo_cumplido(db_session):
    _, orden, dispositivo = _crear_caso_orden_dispositivo(
        db_session, estado_dispositivo=EstadoDispositivo.OBJETIVO_CUMPLIDO
    )
    _autorizar_operador(db_session, orden, "operador1")

    resultado = evaluar_gating(db_session, dispositivo_id=dispositivo.id, username="operador1")

    assert resultado.autorizado is False
    assert resultado.motivo_rechazo == MotivoRechazoGating.DISPOSITIVO_OBJETIVO_CUMPLIDO


def test_rechaza_hallazgo_casual_sin_aprobar(db_session):
    _, orden, dispositivo = _crear_caso_orden_dispositivo(
        db_session, es_hallazgo_casual=True, hallazgo_casual_aprobado_por=None
    )
    _autorizar_operador(db_session, orden, "operador1")

    resultado = evaluar_gating(db_session, dispositivo_id=dispositivo.id, username="operador1")

    assert resultado.autorizado is False
    assert resultado.motivo_rechazo == MotivoRechazoGating.HALLAZGO_CASUAL_SIN_APROBAR


def test_autoriza_hallazgo_casual_ya_aprobado(db_session):
    _, orden, dispositivo = _crear_caso_orden_dispositivo(
        db_session, es_hallazgo_casual=True, hallazgo_casual_aprobado_por="Juez Test"
    )
    _autorizar_operador(db_session, orden, "operador1")

    resultado = evaluar_gating(db_session, dispositivo_id=dispositivo.id, username="operador1")

    assert resultado.autorizado is True


def test_rechaza_fuera_de_ventana_temporal(db_session):
    ahora = utc_now()
    _, orden, dispositivo = _crear_caso_orden_dispositivo(
        db_session,
        vigente_desde=ahora - timedelta(days=10),
        vigente_hasta=ahora - timedelta(days=1),  # ya vencida
    )
    _autorizar_operador(db_session, orden, "operador1")

    resultado = evaluar_gating(db_session, dispositivo_id=dispositivo.id, username="operador1")

    assert resultado.autorizado is False
    assert resultado.motivo_rechazo == MotivoRechazoGating.ORDEN_FUERA_DE_VENTANA


def test_autoriza_dentro_de_prorroga_aunque_vigente_hasta_ya_paso(db_session):
    ahora = utc_now()
    _, orden, dispositivo = _crear_caso_orden_dispositivo(
        db_session,
        vigente_desde=ahora - timedelta(days=10),
        vigente_hasta=ahora - timedelta(days=1),
        prorroga_hasta=ahora + timedelta(days=5),
    )
    _autorizar_operador(db_session, orden, "operador1")

    resultado = evaluar_gating(db_session, dispositivo_id=dispositivo.id, username="operador1")

    assert resultado.autorizado is True


def test_rechaza_orden_cesada(db_session):
    _, orden, dispositivo = _crear_caso_orden_dispositivo(db_session, estado_orden=EstadoOrden.CESADA)
    _autorizar_operador(db_session, orden, "operador1")

    resultado = evaluar_gating(db_session, dispositivo_id=dispositivo.id, username="operador1")

    assert resultado.autorizado is False
    assert resultado.motivo_rechazo == MotivoRechazoGating.ORDEN_NO_VIGENTE


def test_rechaza_operador_no_autorizado(db_session):
    _, orden, dispositivo = _crear_caso_orden_dispositivo(db_session)
    # No se autoriza a ningun operador

    resultado = evaluar_gating(db_session, dispositivo_id=dispositivo.id, username="desconocido")

    assert resultado.autorizado is False
    assert resultado.motivo_rechazo == MotivoRechazoGating.OPERADOR_NO_AUTORIZADO


def test_rechaza_operador_revocado(db_session):
    _, orden, dispositivo = _crear_caso_orden_dispositivo(db_session)
    personal = _autorizar_operador(db_session, orden, "operador1")
    personal.revocado_en = utc_now()
    personal.revocado_motivo = "cambio de asignacion"
    db_session.flush()

    resultado = evaluar_gating(db_session, dispositivo_id=dispositivo.id, username="operador1")

    assert resultado.autorizado is False
    assert resultado.motivo_rechazo == MotivoRechazoGating.OPERADOR_REVOCADO
