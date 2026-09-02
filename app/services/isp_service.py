"""
Sharur SAIC - app/services/isp_service.py

Placeholder de enlace con proveedores de servicios de Internet
(ISP), previsto en el flujo original como "pendiente, al final".

El Art. 284 CPP Misiones habilita el deber de colaboracion de
proveedores para la obtencion de evidencia digital. Este modulo
define la interfaz esperada para cuando se implemente la
integracion real (probablemente via oficio electronico /
API especifica del proveedor u organismo regulador), sin
implementar todavia ningun conector concreto.

Al integrarse, cada solicitud a un ISP deberia:
1. Registrarse en la auditoria del caso (evento propio, agregar
   TipoEvento.SOLICITUD_ISP si se implementa).
2. Quedar vinculada a una Orden vigente (mismo principio de
   gating que el resto del sistema).
3. Guardar la respuesta del proveedor como anexo en export.py.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class SolicitudISP:
    caso_id: int
    orden_id: int
    proveedor: str
    tipo_solicitud: str  # ej: "identificacion_abonado", "trafico_ip", "geolocalizacion"
    identificador_objetivo: str
    justificacion: str


@dataclass
class RespuestaISP:
    solicitud: SolicitudISP
    recibida: bool
    contenido: Optional[str] = None
    hash_contenido: Optional[str] = None
    notas: str = "Integracion pendiente de implementacion."


def enviar_solicitud(solicitud: SolicitudISP) -> RespuestaISP:
    """
    NO IMPLEMENTADO. Punto de extension para cuando se defina el
    canal formal de comunicacion con cada proveedor (oficio
    electronico, portal de cumplimiento legal del proveedor, etc.).
    """
    raise NotImplementedError(
        "El enlace con ISP esta pendiente de definicion e implementacion, "
        "tal como se preveo en el diseno original del sistema."
    )
