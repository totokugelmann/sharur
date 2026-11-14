"""
Sharur SAIC - app/services/analisis_ia_service.py
"""

import re
from typing import Optional
from sqlalchemy.orm import Session

from app.core.logging import logger
from app.models.auditoria import TipoEvento
from app.models.hallazgo import ConfianzaHallazgo, Hallazgo, SeveridadHallazgo
from app.services import auditoria_service
from app.services.cve_search_service import (
    ESTADO_NO_DISPONIBLE,
    ESTADO_VERIFICADO,
    buscar_cves_por_producto,
    is_cve,
    verificar_cve_en_nvd,
)
from app.services.llm_service import build_evidence_blob, find_quote_source, proponer_hallazgos
from app.services.nmap_parser import evidencia_compacta, parsear_nmap

_MAPA_SEVERIDAD = {
    "critica": SeveridadHallazgo.CRITICA,
    "alta": SeveridadHallazgo.ALTA,
    "media": SeveridadHallazgo.MEDIA,
    "baja": SeveridadHallazgo.BAJA,
    "informativa": SeveridadHallazgo.INFORMATIVA,
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

def _normalizar_severidad(valor: Optional[str]) -> SeveridadHallazgo:
    if not valor:
        return SeveridadHallazgo.INFORMATIVA
    return _MAPA_SEVERIDAD.get(valor.strip().lower(), SeveridadHallazgo.INFORMATIVA)

def severidad_desde_cvss(score: Optional[float], por_defecto: SeveridadHallazgo) -> SeveridadHallazgo:
    if score is None:
        return por_defecto
    if score >= 9.0:
        return SeveridadHallazgo.CRITICA
    if score >= 7.0:
        return SeveridadHallazgo.ALTA
    if score >= 4.0:
        return SeveridadHallazgo.MEDIA
    return SeveridadHallazgo.BAJA


def limpiar_cves_no_verificados(texto: str, verificados: set[str]) -> str:
    return CVE_RE.sub(lambda m: m.group(0) if m.group(0) in verificados else "[CVE no verificado]", texto)


def _registrar_hallazgo(
    db: Session, *, caso_id: int, username: str, dispositivo_id: Optional[int],
    herramienta: str, resultado_tool, cve_id: Optional[str], titulo: str,
    descripcion: str, cita: str, severidad: SeveridadHallazgo,
    confianza: ConfianzaHallazgo, nvd_verificado: bool, nvd_score: Optional[float],
) -> Hallazgo:
    hallazgo = Hallazgo(
        caso_id=caso_id, dispositivo_id=dispositivo_id, herramienta_origen=herramienta,
        comando_ejecutado=" ".join(resultado_tool.command),
        cve_id=cve_id if nvd_verificado else None,
        titulo=titulo, descripcion=descripcion, cita_evidencia=cita,
        evidencia_cruda_hash=resultado_tool.evidence_hash,
        severidad=severidad, confianza=confianza,
        nvd_verificado=nvd_verificado, nvd_score=nvd_score,
    )
    db.add(hallazgo)
    db.flush()

    tipo = (
        TipoEvento.HALLAZGO_DESCARTADO
        if confianza == ConfianzaHallazgo.DESCARTADA else TipoEvento.HALLAZGO_VALIDADO
    )
    auditoria_service.registrar_evento(
        db, caso_id=caso_id, tipo_evento=tipo,
        descripcion=f"Hallazgo '{titulo}' -> confianza={confianza.value}.",
        actor_username=username, dispositivo_id=dispositivo_id,
        detalle={
            "hallazgo_id": hallazgo.id, "cve_id": cve_id,
            "confianza": confianza.value, "nvd_verificado": nvd_verificado,
            "cita_evidencia": cita,
        },
    )
    return hallazgo


def analizar_evidencia(
    db: Session,
    caso_id: int,
    username: str,
    herramienta: str,
    resultado_tool,
    dispositivo_id: Optional[int] = None,
) -> list[Hallazgo]:
    """
    Dos vias:
      1. Determinista (nmap): por cada puerto con producto+version se buscan
         en NVD los CVEs que lo afectan. Cita = linea del puerto. Resultado
         CONFIRMADA (hay evidencia textual y verificacion NVD, regla R-05).
      2. LLM: propone hallazgos adicionales con cita textual; si traen un CVE
         se verifica en NVD. Sin verificacion queda PROBABLE.
    Si la NVD no responde, nada se marca como verificado y se avisa.
    """
    if resultado_tool.status not in ("ok", "error"):
        return []

    texto_para_ia = resultado_tool.output
    puertos = []

    if herramienta == "nmap":
        puertos = parsear_nmap(texto_para_ia)
        if not puertos:
            logger.info("Nmap no encontro puertos abiertos. Omitiendo analisis.")
            return []
        texto_para_ia = evidencia_compacta(puertos)

    auditoria_service.registrar_evento(
        db, caso_id=caso_id, tipo_evento=TipoEvento.HALLAZGO_IA_PROPUESTO,
        descripcion=f"Evidencia de '{herramienta}' enviada a analisis.",
        actor_username=username, dispositivo_id=dispositivo_id,
        detalle={"herramienta": herramienta, "evidencia_hash": resultado_tool.evidence_hash},
    )

    comunes = dict(
        caso_id=caso_id, username=username, dispositivo_id=dispositivo_id,
        herramienta=herramienta, resultado_tool=resultado_tool,
    )
    hallazgos: list[Hallazgo] = []
    cves_ya_registrados: set[str] = set()
    nvd_caida = False

    # ── Via 1: busqueda determinista por producto + version ──────────
    for pt in puertos:
        if not (pt.producto and pt.version):
            continue
        res = buscar_cves_por_producto(pt.producto, pt.version)
        if res.estado == ESTADO_NO_DISPONIBLE:
            nvd_caida = True
            logger.warning("NVD no disponible para %s %s: %s", pt.producto, pt.version, res.error)
            continue
        for cve in res.cves:
            if cve.cve_id in cves_ya_registrados:
                continue
            cves_ya_registrados.add(cve.cve_id)
            hallazgos.append(_registrar_hallazgo(
                db, cve_id=cve.cve_id,
                titulo=f"{cve.cve_id} en {pt.producto} {pt.version} (puerto {pt.puerto}/{pt.protocolo})",
                descripcion=f"[NVD] {cve.descripcion}",
                cita=pt.linea,
                severidad=severidad_desde_cvss(cve.cvss_score, SeveridadHallazgo.MEDIA),
                confianza=ConfianzaHallazgo.CONFIRMADA,
                nvd_verificado=True, nvd_score=cve.cvss_score, **comunes,
            ))

    # ── Via 2: propuestas del LLM ────────────────────────────────────
    evidence_blob = build_evidence_blob(herramienta, texto_para_ia)
    try:
        propuestas, fue_truncado = proponer_hallazgos(evidence_blob)
    except ConnectionError as exc:
        # Los hallazgos deterministas (NVD) no dependen del LLM: se conservan.
        logger.error("LLM no disponible: %s", exc)
        print(f"\n[!] El modelo local no respondio ({exc}). Se informan solo los CVEs hallados por producto/version.")
        propuestas, fue_truncado = [], False

    if fue_truncado:
        print(f"\n[!] ADVERTENCIA: El modelo genero demasiados datos y se corto. Se recuperaron {len(propuestas)} hallazgos.")
        auditoria_service.registrar_evento(
            db, caso_id=caso_id, tipo_evento=TipoEvento.HALLAZGO_IA_PROPUESTO,
            descripcion=f"Respuesta del modelo truncada. Se recuperaron {len(propuestas)} hallazgos parciales.",
            actor_username=username, dispositivo_id=dispositivo_id,
            detalle={"recuperados": len(propuestas)},
        )

    for propuesta in propuestas:
        cita = propuesta.get("cita_evidencia", "")
        cve_id = (propuesta.get("cve_id") or "").strip().upper() or None
        titulo = propuesta.get("titulo", "Hallazgo sin titulo")
        descripcion = propuesta.get("descripcion", "")
        severidad = _normalizar_severidad(propuesta.get("severidad_sugerida"))
        nvd_verificado, nvd_score = False, None

        if not find_quote_source(cita, texto_para_ia):
            confianza = ConfianzaHallazgo.DESCARTADA
        else:
            confianza = ConfianzaHallazgo.PROBABLE
            if cve_id and is_cve(cve_id):
                if cve_id in cves_ya_registrados:
                    continue  # ya lo informo la via determinista
                v = verificar_cve_en_nvd(cve_id)
                if v.existe:
                    nvd_verificado, nvd_score = True, v.cvss_score
                    confianza = ConfianzaHallazgo.CONFIRMADA
                    severidad = severidad_desde_cvss(v.cvss_score, severidad)
                    cves_ya_registrados.add(cve_id)
                    if v.descripcion:
                        descripcion = f"{descripcion}\n\n[NVD] {v.descripcion}"
                elif v.estado == ESTADO_NO_DISPONIBLE:
                    nvd_caida = True
                    descripcion = f"{descripcion}\n\n[NVD no disponible: CVE sin verificar]"
                # estado no_existe: el CVE era inventado; se descarta el ID y queda PROBABLE

        if not nvd_verificado:
            descripcion = limpiar_cves_no_verificados(descripcion, set())

        hallazgos.append(_registrar_hallazgo(
            db, cve_id=cve_id, titulo=titulo, descripcion=descripcion, cita=cita,
            severidad=severidad, confianza=confianza,
            nvd_verificado=nvd_verificado, nvd_score=nvd_score, **comunes,
        ))

    if nvd_caida:
        print("\n[!] La NVD no respondio: los hallazgos sin CVE NO estan verificados. Reintenta mas tarde.")
        auditoria_service.registrar_evento(
            db, caso_id=caso_id, tipo_evento=TipoEvento.HALLAZGO_IA_PROPUESTO,
            descripcion="NVD no disponible durante el analisis: verificacion de CVEs incompleta.",
            actor_username=username, dispositivo_id=dispositivo_id,
            detalle={"estado": ESTADO_NO_DISPONIBLE},
        )

    # Puertos con version que ningun hallazgo cubre (aviso, no inventa nada)
    citas = " ".join(h.cita_evidencia for h in hallazgos)
    sin_cobertura = [pt for pt in puertos if pt.linea not in citas and pt.linea.split()[0] not in citas]
    if sin_cobertura:
        print("[i] Puertos sin hallazgos: " + ", ".join(f"{p.puerto}/{p.protocolo}" for p in sin_cobertura))

    return hallazgos


# ── Inventario de dispositivos (determinista, sin LLM) ───────────────
_IP_MAC_RE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s*(.*)$")
_HOST_RE = re.compile(r"Nmap scan report for (?:\S+ \()?(\d{1,3}(?:\.\d{1,3}){3})")
_PUERTO_ABIERTO_RE = re.compile(r"^(\d+)/(?:tcp|udp)\s+open")

_PISTAS_FABRICANTE = [
    (("cisco", "tp-link", "d-link", "netgear", "ubiquiti", "mikrotik", "huawei", "zte", "arris"), "Router / equipo de red"),
    (("apple", "samsung", "xiaomi", "oppo", "motorola", "oneplus"), "Telefono / dispositivo movil"),
    (("raspberry",), "Single-board computer"),
    (("vmware", "virtualbox", "pcs systemtechnik", "qemu"), "Maquina virtual"),
    (("hikvision", "dahua", "axis"), "Camara IP"),
    (("hp", "hewlett", "canon", "epson", "brother", "xerox"), "Impresora"),
    (("intel", "dell", "lenovo", "asustek", "gigabyte", "realtek"), "PC / notebook"),
]
_PISTAS_PUERTOS = {
    554: "Camara IP / streaming", 9100: "Impresora", 631: "Impresora",
    3389: "PC Windows (RDP)", 445: "PC / servidor (SMB)", 22: "Servidor / equipo con SSH",
}


def identificar_dispositivos_red(
    db: Session, caso_id: int, username: str, resultado_arp, resultado_nmap_puertos=None
) -> list[dict]:
    """
    Inventario por heuristica: IP+MAC+fabricante (arp-scan/netdiscover) y
    puertos abiertos (nmap). 'razon' explica en que se basa cada tipo; la
    confianza es 'media' si hay dos pistas coincidentes, 'baja' si hay una.
    """
    hosts: dict[str, dict] = {}
    for linea in (resultado_arp.output or "").splitlines():
        m = _IP_MAC_RE.match(linea)
        if m:
            ip, mac, resto = m.groups()
            hosts[ip] = {"ip": ip, "mac": mac.lower(), "fabricante": resto.strip(), "puertos": []}

    actual = None
    if resultado_nmap_puertos is not None:
        for linea in (resultado_nmap_puertos.output or "").splitlines():
            h = _HOST_RE.search(linea)
            if h:
                actual = hosts.setdefault(
                    h.group(1), {"ip": h.group(1), "mac": "desconocida", "fabricante": "", "puertos": []}
                )
                continue
            p = _PUERTO_ABIERTO_RE.match(linea.strip())
            if p and actual is not None:
                actual["puertos"].append(int(p.group(1)))

    inventario = []
    for ip in sorted(hosts, key=lambda x: tuple(int(o) for o in x.split("."))):
        d = hosts[ip]
        pistas = []
        fab = d["fabricante"].lower()
        for claves, tipo in _PISTAS_FABRICANTE:
            if any(c in fab for c in claves):
                pistas.append((tipo, f"fabricante '{d['fabricante']}'"))
                break
        for pto in d["puertos"]:
            if pto in _PISTAS_PUERTOS:
                pistas.append((_PISTAS_PUERTOS[pto], f"puerto {pto} abierto"))
                break

        if pistas:
            tipo = pistas[0][0]
            razon = "; ".join(r for _, r in pistas)
            confianza = "media" if len(pistas) > 1 else "baja"
        else:
            tipo, razon, confianza = "Indeterminado", "sin pistas de fabricante ni de puertos", "baja"
        inventario.append({"ip": ip, "mac": d["mac"], "tipo": tipo, "confianza": confianza, "razon": razon})

    return inventario
