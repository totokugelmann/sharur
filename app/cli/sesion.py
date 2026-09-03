"""
Sharur SAIC - app/cli/sesion.py

Arranque de sesion del CLI: identificacion del operador, y
creacion o seleccion de un Caso con su Orden y alcance (limites)
ya cargados.

Este modulo llama directo a los mismos servicios que usa la API
HTTP (orden_service, caso_service) -- no hay dos implementaciones
del flujo de negocio, el CLI es simplemente otra puerta de
entrada a la misma logica ya gateada y auditada.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.cli import ui
from app.models.caso import Caso, EstadoCaso
from app.models.dispositivo import Dispositivo, EstadoDispositivo, TipoDispositivo
from app.models.orden import Orden, PersonalAutorizado
from app.services import caso_service, orden_service


def identificar_operador() -> str:
    ui.titulo("SHARUR SAIC — Identificación de operador")
    ui.info(
        "Ingresá tu usuario. Debe coincidir con el registrado como personal "
        "autorizado en la orden del caso que vayas a operar; si no coincide, "
        "el sistema va a rechazar cada acción (gating por operador)."
    )
    return ui.prompt("Usuario")


def elegir_o_crear_caso(db: Session, username: str) -> Caso:
    casos_abiertos = (
        db.query(Caso)
        .filter(Caso.estado.in_([EstadoCaso.ABIERTO, EstadoCaso.EN_CURSO]))
        .order_by(Caso.id.desc())
        .all()
    )

    opciones = [("nuevo", "Crear un caso nuevo")]
    for caso in casos_abiertos:
        opciones.append((f"caso:{caso.id}", f"[{caso.id}] {caso.numero_causa} — {caso.caratula}"))

    eleccion = ui.menu("Casos disponibles", opciones)

    if eleccion == "nuevo":
        return _crear_caso_interactivo(db, username)

    caso_id = int(eleccion.split(":")[1])
    return db.get(Caso, caso_id)


def _crear_caso_interactivo(db: Session, username: str) -> Caso:
    ui.subtitulo("Nuevo caso")
    datos = {
        "numero_causa": ui.prompt("Número de causa"),
        "caratula": ui.prompt("Carátula"),
        "juzgado_interviniente": ui.prompt("Juzgado interviniente"),
        "fiscalia_interviniente": ui.prompt("Fiscalía interviniente", requerido=False) or None,
        "descripcion": ui.prompt("Descripción (opcional)", requerido=False) or None,
    }
    caso = caso_service.crear_caso(db, datos, creado_por=username)
    db.commit()
    db.refresh(caso)
    ui.ok(f"Caso creado: id={caso.id}")
    return caso


def elegir_o_cargar_orden(db: Session, caso: Caso, username: str) -> Orden:
    ordenes = db.query(Orden).filter(Orden.caso_id == caso.id).order_by(Orden.id.desc()).all()

    if not ordenes:
        ui.advertencia("Este caso todavía no tiene ninguna orden cargada. Es obligatorio cargar una antes de poder operar.")
        return _cargar_orden_interactiva(db, caso, username)

    opciones = [("nueva", "Cargar una orden nueva para este caso")]
    for orden in ordenes:
        opciones.append((f"orden:{orden.id}", f"[{orden.id}] {orden.numero_orden} ({orden.estado.value})"))

    eleccion = ui.menu(f"Órdenes del caso '{caso.numero_causa}'", opciones)

    if eleccion == "nueva":
        return _cargar_orden_interactiva(db, caso, username)

    orden_id = int(eleccion.split(":")[1])
    return db.get(Orden, orden_id)


def _parse_fecha(valor: str) -> datetime:
    """Acepta 'YYYY-MM-DD' o 'YYYY-MM-DDTHH:MM'; asume UTC si no se especifica offset."""
    valor = valor.strip()
    formatos = ("%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S")
    for fmt in formatos:
        try:
            dt = datetime.strptime(valor, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"Formato de fecha no reconocido: '{valor}'. Usá YYYY-MM-DD o YYYY-MM-DDTHH:MM.")


def _prompt_fecha(mensaje: str, default: Optional[datetime] = None) -> datetime:
    default_str = default.strftime("%Y-%m-%d") if default else None
    while True:
        valor = ui.prompt(f"{mensaje} (YYYY-MM-DD)", default=default_str)
        try:
            return _parse_fecha(valor)
        except ValueError as exc:
            print(f"    {exc}")


def _cargar_orden_interactiva(db: Session, caso: Caso, username: str) -> Orden:
    ui.titulo("Carga de orden judicial y alcance (Art. 285 CPP Misiones)")
    ui.info("Estos datos son obligatorios: sin fundamento y ventana temporal, no hay orden válida.")

    ahora = datetime.now(timezone.utc)

    datos = {
        "numero_orden": ui.prompt("Número de orden"),
        "juez_firmante": ui.prompt("Juez firmante"),
        "fecha_emision": _prompt_fecha("Fecha de emisión", default=ahora),
        "vigente_desde": _prompt_fecha("Vigente desde", default=ahora),
        "vigente_hasta": _prompt_fecha("Vigente hasta", default=ahora + timedelta(days=15)),
        "fundamento_proporcionalidad": ui.prompt("Fundamento de proporcionalidad"),
        "fundamento_necesidad": ui.prompt("Fundamento de necesidad"),
        "fundamento_idoneidad": ui.prompt("Fundamento de idoneidad"),
        "imputado_identificacion": ui.prompt("Identificación del imputado"),
        "defensor_nombre": ui.prompt("Nombre del defensor", requerido=False) or None,
        "defensor_contacto": ui.prompt("Contacto del defensor", requerido=False) or None,
    }

    orden = orden_service.crear_orden(db, caso.id, datos, actor_username=username)
    db.commit()
    db.refresh(orden)
    ui.ok(f"Orden cargada: id={orden.id}")

    ui.subtitulo("Personal autorizado (Art. 285 exige detallar quién interviene)")
    ui.info(f"Agregá al menos tu propio usuario ('{username}') para poder operar en el paso siguiente.")
    while True:
        agregar_personal_autorizado(db, orden, username)
        if not ui.prompt_si_no("¿Agregar otra persona autorizada?", default=False):
            break

    ui.subtitulo("Dispositivos dentro del alcance de esta orden")
    ui.info("Cada dispositivo es un target concreto (IP, dominio, etc.) con su propio sub-alcance de datos.")
    while True:
        agregar_dispositivo(db, orden, username)
        if not ui.prompt_si_no("¿Agregar otro dispositivo?", default=False):
            break

    db.refresh(orden)
    return orden


def agregar_personal_autorizado(db: Session, orden: Orden, actor_username: str) -> PersonalAutorizado:
    datos = {
        "username": ui.prompt("  Usuario del operador"),
        "nombre_completo": ui.prompt("  Nombre completo"),
        "legajo": ui.prompt("  Legajo", requerido=False) or None,
        "rol_funcional": ui.prompt("  Rol funcional (ej: perito informático)"),
    }
    personal = orden_service.agregar_personal_autorizado(db, orden, datos, actor_username=actor_username)
    db.commit()
    ui.ok(f"Personal autorizado agregado: {personal.username}")
    return personal


_TIPOS_DISPOSITIVO = {
    "1": TipoDispositivo.HOST_RED,
    "2": TipoDispositivo.API_BACKEND,
    "3": TipoDispositivo.DISPOSITIVO_MOVIL,
    "4": TipoDispositivo.OTRO,
}


def agregar_dispositivo(db: Session, orden: Orden, actor_username: str) -> Dispositivo:
    ui.info("  Tipo de dispositivo: 1) host_red  2) api_backend  3) dispositivo_movil  4) otro")
    tipo_codigo = ui.prompt("  Tipo", default="1")
    tipo = _TIPOS_DISPOSITIVO.get(tipo_codigo, TipoDispositivo.HOST_RED)

    datos = {
        "tipo": tipo,
        "identificador": ui.prompt("  Identificador (IP / dominio / IMEI, etc.)"),
        "descripcion": ui.prompt("  Descripción", requerido=False) or None,
        "sub_alcance_datos": ui.prompt("  Sub-alcance de datos autorizado sobre este dispositivo"),
    }
    dispositivo = orden_service.agregar_dispositivo(db, orden, datos, actor_username=actor_username)
    db.commit()
    ui.ok(f"Dispositivo agregado: id={dispositivo.id} ({dispositivo.identificador})")
    return dispositivo


def elegir_dispositivo(db: Session, orden: Orden, username: str) -> Optional[Dispositivo]:
    dispositivos = (
        db.query(Dispositivo)
        .filter(Dispositivo.orden_id == orden.id, Dispositivo.estado != EstadoDispositivo.EXCLUIDO)
        .order_by(Dispositivo.id.asc())
        .all()
    )

    if not dispositivos:
        ui.advertencia("Esta orden no tiene dispositivos cargados todavía.")
        if ui.prompt_si_no("¿Agregar uno ahora?", default=True):
            return agregar_dispositivo(db, orden, actor_username=username)
        return None

    opciones = []
    for d in dispositivos:
        etiqueta = f"[{d.id}] {d.identificador} ({d.tipo.value}) — {d.estado.value}"
        opciones.append((f"disp:{d.id}", etiqueta))
    opciones.append(("nuevo", "Agregar un nuevo dispositivo a esta orden"))

    eleccion = ui.menu("Dispositivos de esta orden", opciones)

    if eleccion == "nuevo":
        return agregar_dispositivo(db, orden, actor_username=username)

    dispositivo_id = int(eleccion.split(":")[1])
    return db.get(Dispositivo, dispositivo_id)
