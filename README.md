# Sharur SAIC

## 1. Identificación

| | |
|---|---|
| **Proyecto** | Sharur — framework de adquisición estática de evidencia y análisis de red para la Secretaría de Apoyo para Investigaciones Complejas (SAIC) |
| **Autor** | Kugelmann, Tomás Ezequiel |
| **Comisión** | A · Sede Posadas |
| **Carrera** | Ingeniería en Sistemas de Información · Universidad de la Cuenca del Plata |
| **Actividad** | Proyecto Integrador Final · Actividad de Evaluación N.º 2 |
| **Etiqueta** | `v2.0` — MVP completo (gestión y auditoría + análisis de red, IA y consola) |

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

Sharur corre en Linux (Debian, Ubuntu, Kali), WSL2 o Windows 11. Las tres herramientas base —**Python 3.12 o superior** (probado con 3.12 y 3.13), **Git 2.x** y **PostgreSQL 14 o superior**— no se dan por supuestas: instalarlas es el primer paso de la sección 4 (§4.1), por si todavía no las tenés en el equipo.

Las dependencias de Python se instalan desde `requirements.txt`: SQLAlchemy 2.0.30 o superior, Pydantic 2.7.0 o superior, pydantic-settings 2.2.1 o superior, python-dotenv 1.0.1 o superior, psycopg2-binary 2.9.9 o superior, requests 2.31.0 o superior (NVD y Ollama) y Rich 13.7.0 o superior (presentación de la consola).

**Herramientas de sistema** (para los módulos de red y la consola): `nmap`, `arp-scan` y `netdiscover`. En Kali vienen preinstaladas; en otras distribuciones se instalan con el gestor de paquetes (por ejemplo `sudo apt install nmap arp-scan netdiscover`). Varias requieren privilegios de red (`sudo` o *capabilities*). La consola libre también reconoce binarios de reconocimiento como `whois`, `dig` y `curl` si están presentes.

**Modelo de inteligencia artificial local (opcional).** El análisis asistido usa [Ollama](https://ollama.com) corriendo el modelo definido en `.env`. No es necesario para la gestión, la auditoría ni el descubrimiento de red: sólo para el enriquecimiento y el análisis de vulnerabilidades. El análisis se ejecuta sobre CPU de la máquina virtual; se recomienda un modelo de **4B para VMs** y de **9B para máquinas host** con mayor capacidad.

**Exportación a PDF (opcional).** El informe se genera siempre en HTML. Para obtener PDF nativo debe instalarse el motor `weasyprint` y sus librerías de sistema (`libpango`, `libpangocairo`, `libgdk-pixbuf`); si no está, Sharur entrega el HTML (que puede imprimirse a PDF desde el navegador) y lo informa.

---

## 4. Instalación

Ejecutar los pasos en este orden.

### 4.1 Instalar las herramientas base (si no las tenés)

Sharur necesita Python 3.12 o superior, Git 2.x y PostgreSQL 14 o superior. Si ya los tenés instalados, saltar a §4.2.

**Linux (Debian / Ubuntu / Kali):**

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip postgresql postgresql-contrib
# Herramientas de red para los módulos de descubrimiento (en Kali ya vienen):
sudo apt install -y nmap arp-scan netdiscover
# Arrancar el servicio de base de datos:
sudo service postgresql start          # o: sudo systemctl enable --now postgresql
```

**Windows 11 (PowerShell, con winget):**

```powershell
winget install Git.Git
winget install Python.Python.3.12
winget install PostgreSQL.PostgreSQL
```

Comprobar que quedó todo disponible:

```bash
python3 --version    # 3.12 o superior
git --version        # 2.x
psql --version       # 14 o superior
```

### 4.2 Preparar la base de datos

La forma recomendada es el script `scripts/init_db.sql`, que deja la base en un estado conocido y **se puede volver a correr cuantas veces haga falta**: borra lo anterior, recrea la base `sharur_db`, el usuario `sharur_user` y sus permisos, y alinea la versión de *collation* del template con la del sistema (necesario en Kali *rolling* tras actualizar `glibc`).

En Linux, PostgreSQL usa autenticación *peer* para conexiones locales (el usuario del sistema debe coincidir con el rol, por eso `psql -U postgres` desde tu usuario falla con *"Peer authentication failed"*). Se ejecuta como el usuario `postgres` del sistema:

```bash
sudo -u postgres psql -f scripts/init_db.sql
```

En Windows, abrir **SQL Shell (psql)** como usuario `postgres` (o el Query Tool de pgAdmin) y ejecutar `\i scripts/init_db.sql`.

<details>
<summary>Equivalente paso a paso (si no se quiere usar el script)</summary>

Entrar como superusuario (`sudo -u postgres psql`) y ejecutar:

```sql
DROP DATABASE IF EXISTS sharur_db;
DROP ROLE IF EXISTS sharur_user;

ALTER DATABASE template1 REFRESH COLLATION VERSION;   -- evita el error de collation en Kali rolling

CREATE USER sharur_user WITH PASSWORD 'sharur_pass';
CREATE DATABASE sharur_db OWNER sharur_user;
GRANT ALL PRIVILEGES ON DATABASE sharur_db TO sharur_user;

\c sharur_db
GRANT ALL ON SCHEMA public TO sharur_user;            -- necesario en PostgreSQL 15 o superior
```

</details>

### 4.3 Clonar el repositorio y posicionarse en la etiqueta

```bash
git clone https://github.com/totokugelmann/sharur.git
cd sharur
git checkout v2.0
```

### 4.4 Instalar las dependencias

Crear un entorno virtual para no alterar los paquetes del sistema.

**Linux / WSL:**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell):**

```powershell
python -m venv venv
# Si la ejecución de scripts está restringida, ejecutar primero:
# Set-ExecutionPolicy Unrestricted -Scope CurrentUser
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 4.5 Modelo de IA local (opcional)

Sólo si se van a usar el enriquecimiento o el análisis de vulnerabilidades. Instalar Ollama y descargar el modelo indicado en `.env` (`OLLAMA_MODEL`):

```bash
# Instalar Ollama (ver https://ollama.com) y luego, por ejemplo:
ollama pull qwen2.5:4b     # variante liviana, recomendada para VMs
ollama serve               # deja el motor escuchando en localhost:11434
```

El `Modelfile` del repositorio documenta el modelo de referencia del proyecto.

---

## 5. Configuración

El archivo de variables se genera a partir del de ejemplo.

**Linux / WSL:**

```bash
cp .env.example .env
nano .env
```

**Windows:**

```powershell
copy .env.example .env
notepad .env
```

El `.env.example` ya trae el `DATABASE_URL` apuntando a la base y credenciales que crea el script de la §4.2, así que con `cp .env.example .env` normalmente no hace falta editar nada. Sólo cambialo si usaste otra contraseña o nombre de base:

```
DATABASE_URL=postgresql+psycopg2://sharur_user:sharur_pass@localhost:5432/sharur_db
```

Significado de las variables principales:

| Variable | Significado |
|---|---|
| `APP_ENV` | Entorno de ejecución (`development`). |
| `DATABASE_URL` | Cadena de conexión a PostgreSQL: usuario, contraseña, servidor, puerto y base. |
| `LOG_LEVEL` | Nivel de detalle del registro de la aplicación (`INFO`). |
| `LOG_DIR`, `REPORTS_DIR`, `EVIDENCE_STORAGE_DIR` | Carpetas locales para registros, reportes y evidencia. |
| `OLLAMA_URL`, `OLLAMA_MODEL`, `OLLAMA_TIMEOUT` | Endpoint, nombre y tiempo máximo del modelo de IA local. |
| `NVD_API_URL`, `NVD_API_KEY`, `NVD_CACHE_PATH`, `NVD_CACHE_TTL_HORAS` | Base nacional de vulnerabilidades: endpoint, clave opcional (mejora el límite de peticiones) y caché local. |

Las variables `OLLAMA_*` y `NVD_*` sólo son necesarias para los módulos de análisis asistido; la gestión de casos, la auditoría y el descubrimiento de red funcionan sin ellas. El `NVD_API_KEY` es opcional pero recomendable para evitar el estrangulamiento de peticiones. El archivo `.env` real no se versiona.

---

## 6. Ejecución y verificación

### 6.1 Arranque

```bash
python sharur_cli.py
```

Sharur no expone ningún puerto ni dirección web: se opera desde la terminal. En el primer arranque crea automáticamente las tablas sobre la base vacía (casos, eventos de auditoría, órdenes, dispositivos, hallazgos y demás), sin pasos manuales de migración.

### 6.2 Recorrido paso a paso

1. En el menú principal, elegir **`[1] Crear caso`**.
2. Ingresar el **número de expediente**, el **número de oficio** y el **operador**. Resultado esperado: `[+] Caso creado — expediente <número>`.
3. En el menú del caso aparecen las opciones de trabajo:
   - **`[1] Detectar hosts en red local`** — descubrimiento con nmap / arp-scan / netdiscover (con opción de enriquecimiento por IA).
   - **`[2] Objetivos`** — escaneo profundo de un objetivo y análisis automático con IA + NVD.
   - **`[3] Consola libre`** — comandos interactivos auditados contra un objetivo autorizado.
   - **`[4] Ver auditoría del caso`** — últimos eventos de la cadena, con su secuencia y su hash SHA-256.
   - **`[5] Exportar informe del caso`** — HTML o PDF, con su hash.
   - **`[6] Salir (cierra el caso)`** — el caso pasa a estado cerrado y se sella el hash de reporte final.

Para una verificación mínima del núcleo auditable, basta con `[1] Crear caso`, revisar **`[4]`** y cerrar con **`[6]`**: el caso queda cerrado con su hash de reporte final.

### 6.3 Verificación de la persistencia

Cerrar la aplicación y consultar la base:

```sql
SELECT numero_causa, estado, hash_reporte_final FROM casos;
SELECT secuencia, hash_evento_anterior, hash_evento FROM eventos_auditoria ORDER BY secuencia;
```

Resultado esperado: el caso figura cerrado con su hash de reporte final, y cada evento conserva el hash del evento anterior, comenzando por un primer evento sin hash previo. Al volver a ejecutar `python sharur_cli.py`, los datos siguen presentes.

### 6.4 Pruebas automatizadas

Con el entorno virtual activado (paso 4.4):

```bash
pip install pytest
pytest -q
```

Resultado esperado: `51 passed`. En distribuciones que protegen el Python del sistema, como Kali o Debian recientes, `pip` solo funciona dentro del entorno virtual activado.

Las pruebas cubren el núcleo auditable (hash determinista, dependencia del evento anterior y detección de alteraciones — RF-08 y RNF-01), el parser de nmap, la búsqueda y el cruce de CVEs contra NVD, el cálculo de riesgo, el pipeline de análisis y la exportación del informe. No requieren base de datos ni modelo de IA.

---

## 7. Limitaciones conocidas y alcance pericial

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

## 8. Estado del canal de construcción

El canal de integración continua se define en `.github/workflows/ci.yml` y se ejecuta con GitHub Actions en cada envío a la rama principal y en cada etiqueta. En una máquina limpia instala Python 3.12 y las dependencias, y ejecuta las pruebas del núcleo auditable.

El registro de corridas, con su resultado y fecha, se consulta en la pestaña **Actions** del repositorio:
https://github.com/totokugelmann/sharur/actions

---

## 9. Declaración de herramientas auxiliares

Conforme al Protocolo de Uso Autorizado de la cátedra:

| Herramienta | Función | Artefacto afectado |
|---|---|---|
| Asistente de inteligencia artificial | Asistencia de programación y redacción de pruebas automatizadas | Código fuente del prototipo y `tests/` |
| Asistente de inteligencia artificial | Asistencia en la redacción de este archivo de lectura y de la configuración del canal de integración continua | `README.md`, `.github/workflows/ci.yml` |

Ninguna herramienta auxiliar se empleó sobre datos de causas judiciales reales: todas las pruebas se ejecutan sobre datos sintéticos.
