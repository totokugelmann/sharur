# Sharur SAIC

Sharur es un framework de evidencia digital para la SAIC. Bajo orden judicial y dentro de un
alcance técnicamente delimitado, permite registrar el flujo completo de una intervención
—creación del caso, orden y alcance, acciones ejecutadas, cierre— con una cadena de custodia
verificable de principio a fin.

La idea central es simple: el sistema controla **cuándo, sobre qué y por cuánto tiempo** se
puede actuar. Eso es lo que lo hace defendible como prueba. Lo que decide cómo se logra el
acceso técnico a un dispositivo específico queda, deliberadamente, fuera de este repositorio.

Sharur es una aplicación de terminal. No tiene API HTTP, no tiene frontend web, no tiene
workers en segundo plano. Todo el flujo se ejecuta desde el CLI, contra una base PostgreSQL
local o accesible por red. Esto es intencional: menos superficie, menos piezas donde algo puede
fallar silenciosamente, y cada acción queda en el mismo proceso que la audita.

---

## Estado actual

Este repositorio es un MVP en construcción. Hoy está funcional el flujo de:

- Creación de caso con expediente, número de oficio y operador.
- Registro automático de la fecha de creación.
- Firma de cada evento en una cadena de auditoría con hash encadenado (SHA-256).
- Cierre manual del caso con hash de reporte final.
- Menú de análisis con estructura por categorías (Redes / Objetivos / Consola libre).

Los módulos de nmap, consola libre y análisis con IA están **como puntos de integración
marcados en el código**, sin ejecución real todavía. La razón es que dependen de `tools_service`
y `consola_service`, que a su vez requieren el modelo de Dispositivo —una pieza que se activa en
la próxima fase, cuando el flujo incluya carga de orden judicial.

---

## Marco legal

El sistema se enmarca en el Código Procesal Penal de Misiones (Ley XIV N° 13), Título III,
Capítulo IX (Arts. 284-287):

- **Art. 284**: orden general de obtención de evidencia digital con deber de colaboración de
  proveedores.
- **Art. 285**: adquisición remota mediante herramientas forenses. Nombra a la SAIC como
  ejecutor y exige —bajo pena de nulidad— que la orden detalle personal, duración, alcance y
  prórroga, que haya cese y eliminación de la herramienta al cumplir el objetivo, notificación
  al imputado/defensor, y fundamento de proporcionalidad, necesidad e idoneidad.
- **Art. 286**: hallazgo casual.
- **Art. 287**: perfil digital encubierto.

A esto se suma el marco general: Constitución Nacional Art. 18, Código Penal Art. 153 bis,
Ley 25.520, Ley 26.388 y Ley 27.411 (Convenio de Budapest).

**Nota importante**: en el MVP, el sistema solo controla y audita las acciones. No incluye
ningún mecanismo técnico de acceso remoto, intrusión o explotación. El módulo de cese registra
el evento auditable —quién, cuándo, con qué comprobante— sin contener el mecanismo de
instalación o desinstalación en el dispositivo. Ese "cómo" es una pieza separada, fuera de este
repositorio, que el sistema trata como caja negra: solo la invoca si pasa el gating y la audita
por completo.

---

## Instalación

### Requisitos

- Linux (probado en Debian, Ubuntu y Kali; Windows funciona vía WSL2).
- Python 3.11 o superior.
- PostgreSQL 14 o superior.
- Git.

Si vas a usar el modelo de IA local (fase siguiente), necesitás además:

- Al menos 8.4 GB de RAM libres para la variante completa de 9B.
- Al menos 4 GB de RAM libres para la variante liviana de 4B.

### Traer el proyecto

```bash
git clone https://github.com/totokugelmann/sharur.git
cd sharur
