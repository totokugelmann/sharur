# Sharur SAIC

## 1. Identificación

| | |
|---|---|
| **Proyecto** | Sharur — framework de adquisición estática de evidencia y análisis de red para la Secretaría de Apoyo para Investigaciones Complejas (SAIC) |
| **Autor** | Kugelmann, Tomás Ezequiel |
| **Comisión** | A · Sede Posadas |
| **Carrera** | Ingeniería en Sistemas de Información · Universidad de la Cuenca del Plata |
| **Actividad** | Proyecto Integrador Final · Actividad de Evaluación N.º 4 (entrega final) |
| **Etiqueta** | `v2.0.1` — mismo código que `v2.0` (MVP completo: gestión y auditoría + análisis de red, IA y consola) más el manual de despliegue, la declaración de IA en cinco campos y las versiones fijadas |
| **Manual de despliegue** | [`MANUAL.md`](MANUAL.md) — procedimiento completo para una máquina limpia |

---

## 2. Qué hace este prototipo

Sharur crea un caso judicial, firma cada evento en una cadena de auditoría con hash SHA-256 encadenado y cierra el caso sellando un hash de reporte final, con persistencia en PostgreSQL. Esa cadena prueba la decisión arquitectónica central del proyecto: la auditoría inalterable (*tamper-evident*) atraviesa las capas de interfaz, lógica y persistencia sin depender de un servicio externo. Modificar o borrar cualquier evento pasado rompe el encadenado de todos los posteriores, y la verificación lo detecta.

Sobre ese núcleo, la v2.0 activa los módulos de trabajo pericial que en el v1 estaban sólo previstos:

- **Detección de hosts en red local** — descubrimiento con `nmap`, `arp-scan` y `netdiscover`, con perfiles de barrido (básico, rápido, profundo, sigiloso) y una opción de *enriquecimiento* que envía la evidencia al modelo de IA para inventariar dispositivos por MAC y puertos.
- **Objetivos (escaneo profundo + análisis IA)** — escaneo de puertos y servicios sobre un objetivo autorizado y análisis automático *evidence-first*: el modelo local propone hallazgos, se contrastan contra la NVD por producto/versión (CPE) y se clasifican por confianza (confirmada / probable / descartada) y severidad, calculando un nivel de riesgo global del caso de forma determinista (no lo decide el LLM).
- **Consola libre auditada** — ejecución interactiva de comandos con lista negra de binarios destructivos y de patrones de inyección, validación estricta del objetivo (bloquea ataques a terceros fuera del target) y registro de cada línea en la auditoría, autorizada o no.
- **Informe del caso** — exportación a HTML (o PDF si hay motor instalado), con su propio hash SHA-256.

Sharur sigue siendo una aplicación de línea de comandos, sin servicio web ni interfaz gráfica. Su arquitectura prevé la ejecución paralela del script principal y del motor de inteligencia artificial local en terminales independientes. La interfaz de consola se presenta con la biblioteca *Rich* (paneles, menús, tablas y colores); si *Rich* no está instalado, degrada automáticamente a texto plano sin interrumpir el flujo.

Requisitos del catálogo que implementa el núcleo auditable: **RF-01** (crear caso), **RF-08** (auditoría encadenada), **RF-12** (cierre con hash final), **RNF-01** (tamper-evidence) y **RNF-02** (operación local por línea de comandos). La v2.0 amplía el alcance a los módulos de descubrimiento de red, análisis asistido por IA con validación contra NVD, consola auditada e informe del caso.

---

## 3. Entorno y dependencias

Sharur corre en distribuciones Linux basadas en Debian (Debian, Ubuntu, Kali). Se verificó en Ubuntu 24.04 LTS y en Kali Linux rolling. Las tres herramientas base —**Python 3.12 o superior** (probado con 3.12 y 3.13), **Git 2.x** y **PostgreSQL 14 o superior**— no se dan por supuestas: su instalación es la sección 2 de `MANUAL.md`.

Las dependencias de Python se instalan desde `requirements.txt`, con versión exacta: SQLAlchemy 2.1.8, pydantic 2.14.3, pydantic-settings 2.16.3, python-dotenv 1.2.4, psycopg2-binary 2.9.13, requests 2.34.2 (NVD y Ollama), rich 15.0.0 (presentación de la consola) y pytest 9.2.0.

**Herramientas de sistema** (para los módulos de red y la consola): `nmap`, `arp-scan` y `netdiscover`. En Kali vienen preinstaladas; en otras distribuciones se instalan con el gestor de paquetes (por ejemplo `sudo apt install nmap arp-scan netdiscover`). Varias requieren privilegios de red (`sudo` o *capabilities*). La consola libre también reconoce binarios de reconocimiento como `whois`, `dig` y `curl` si están presentes.

**Modelo de inteligencia artificial local (opcional).** El análisis asistido usa [Ollama](https://ollama.com) corriendo el modelo definido en `.env`. No es necesario para la gestión, la auditoría ni el descubrimiento de red: sólo para el enriquecimiento y el análisis de vulnerabilidades. El análisis se ejecuta sobre CPU de la máquina virtual; se recomienda un modelo de **4B para VMs** y de **9B para máquinas host** con mayor capacidad.

**Exportación a PDF (opcional).** El informe se genera siempre en HTML. Para obtener PDF nativo debe instalarse el motor `weasyprint` y sus librerías de sistema (`libpango`, `libpangocairo`, `libgdk-pixbuf`); si no está, Sharur entrega el HTML (que puede imprimirse a PDF desde el navegador) y lo informa.

---

## 4. Instalación y ejecución

El procedimiento completo y probado en una máquina limpia está en **[`MANUAL.md`](MANUAL.md)**, en la raíz del repositorio: requisitos previos (sección 2), configuración y variables de `.env` (sección 4), base de datos (sección 5), dependencias, modelo de IA local y arranque (sección 6), recorrido de verificación (sección 8), pruebas automatizadas (sección 9) y problemas frecuentes (sección 10). Este archivo no lo repite, para que haya una sola fuente.

Inicio rápido en una distribución basada en Debian (Debian, Ubuntu o Kali), para quien ya tiene PostgreSQL, nmap, arp-scan y netdiscover:

```bash
git clone https://github.com/totokugelmann/sharur.git && cd sharur && git checkout v2.0.1
sudo -u postgres psql -f scripts/init_db.sql
cp .env.example .env
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
sudo venv/bin/python sharur_cli.py
```

El `.env.example` ya apunta a la base que crea `scripts/init_db.sql`, de modo que no requiere ediciones; el `.env` real no se versiona. Con el entorno virtual activado, `pytest -q` debe informar `51 passed`.

---

## 5. Limitaciones conocidas y alcance pericial

Sharur es una herramienta de **asistencia** al perito, no un sustituto de su criterio. Las siguientes limitaciones son inherentes al diseño del MVP y deben tenerse presentes al redactar el acta.

**1. Falsos positivos en la NVD (CPE matching).**
El motor de búsqueda consulta la NVD cruzando el producto y la versión detectada (CPE). Ocasionalmente, la NVD puede asociar un CVE moderno a una versión de software muy antigua si el rango de afectación del CVE no está bien delimitado.
*Acción del perito:* verificar manualmente el CVE y su fecha de publicación antes de aseverar que la vulnerabilidad es explotable en el equipo allanado.

**2. Falsos negativos (límites del LLM).**
El modelo local (por ejemplo, `Qwen 4B`) tiene un conocimiento limitado comparado con los modelos masivos en la nube. Puede no reconocer vulnerabilidades en software muy específico o propietario, o puede omitir CVEs que sí existen si el texto de Nmap no es lo suficientemente explícito.
*Acción del perito:* el reporte generado por la IA es un punto de partida, no la verdad absoluta. El perito debe contrastar los servicios expuestos con su propio conocimiento.

**3. Limitaciones de red (AP Isolation).**
En redes inalámbricas con aislamiento de clientes (*AP Isolation*), las herramientas de Capa 2 como `arp-scan` fallarán. Sharur advierte sobre esto y recomienda el uso de perfiles de Nmap agresivos o un adaptador USB en modo monitor.
*Acción del perito:* documentar en el acta que la topología de red impidió el descubrimiento completo.

**4. Ingesta manual de evidencia.**
Si bien la consola permite extraer archivos usando `base64` o `netcat`, el sistema **no** empaqueta ni cifra automáticamente los archivos extraídos. La cadena de custodia del archivo físico (el archivo descargado en la máquina del perito) depende de que el operador aplique `sha256sum` y lo documente adecuadamente.

**5. Requisitos de hardware.**
El análisis de IA se ejecuta sobre el CPU de la máquina virtual. En hardware limitado, esto puede demorar entre 1 y 10 minutos según el tamaño del escaneo y el modelo utilizado. Se recomienda el modelo de 4B para VMs y el de 9B para máquinas host con mayor capacidad.

---

## 6. Estado del canal de construcción

El canal de integración continua se define en `.github/workflows/ci.yml` y se ejecuta con GitHub Actions en cada envío a la rama principal y en cada etiqueta. En una máquina limpia instala Python 3.12 y las dependencias, y ejecuta las pruebas del núcleo auditable.

El registro de corridas, con su resultado y fecha, se consulta en la pestaña **Actions** del repositorio:
https://github.com/totokugelmann/sharur/actions

---

## 7. Declaración de herramientas auxiliares (inteligencia artificial)

Conforme al Protocolo de Uso Declarado de la cátedra (apartado 27.2 de la Guía Docente – Parte II). La misma declaración figura en `MANUAL.md` (sección 11) y en la Bitácora Individual del autor.

| Herramienta | Función | Pieza (commit) | Fecha | Verificación posterior del autor |
|---|---|---|---|---|
| Claude (Anthropic) | Canal de integración continua, pruebas de la cadena y `pytest.ini` | 9b8d5ba | 02/10/2026 | `pytest` local 5/5 y corrida exitosa en GitHub Actions |
| Claude (Anthropic) | README de la versión v1 | 6102e4b | 02/10/2026 | Clonado y recorrido en máquina virtual |
| Claude Code (Claude Opus 4.8) | Búsqueda de CVE por producto y versión, riesgo global, exportación del informe y limpieza | 8462e9e | 14/11/2026 | Batería de pruebas y recorrido manual del análisis |
| Claude Code (Claude Opus 4.8) | Registro del CPE coincidente; opción «Volver» del informe; corrección de la exportación | 02bd4ca, 24fe6bc, 7e7c78d | 14/11/2026 | Batería de pruebas y exportación manual del informe |
| Claude Code (Claude Opus 4.8) | Interfaz de consola con rich y corrección del menú de exportación | ada8a12 | 15/11/2026 | 51/51 pruebas y recorrido completo en consola |
| Claude Code (Claude Opus 4.8) | Este archivo de lectura en la v2.0 (limitaciones y alcance pericial) | 04bbd87 | 15/11/2026 | Lectura completa y recorrido de la instalación |
| Claude (Anthropic) | `MANUAL.md`, esta declaración y las versiones fijadas de `requirements.txt` | etiqueta v2.0.1 | 15/11/2026 | Recorrido completo del manual en máquina limpia |

Ninguna herramienta auxiliar se empleó sobre datos de causas judiciales reales: todas las pruebas se ejecutan sobre datos sintéticos.
