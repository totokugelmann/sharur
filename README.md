# Sharur SAIC

Framework de evidencia digital para la SAIC (Secretaría/Área de Investigaciones Criminales):
permite, bajo orden judicial y dentro de un alcance técnicamente delimitado, realizar
**reconocimiento y análisis de dispositivos ya identificados**, con **cadena de custodia
verificable de principio a fin**.

Reescritura sobre la base del framework original *Sharur* (reconocimiento de red/API y análisis
estático de APK, evidence-first con LLM), reestructurado como servicio FastAPI orientado a
gestión de casos judiciales conforme al Código Procesal Penal de Misiones (Ley XIV N° 13).

---

## ⚠️ Alcance y límite deliberado del sistema

Este sistema **gobierna cuándo, sobre qué y por cuánto tiempo se puede actuar**. Esa es la
propiedad que lo hace defendible como prueba: cada acción queda validada contra un alcance
autorizado explícito y auditada con hash encadenado, de forma tal que cualquier alteración
posterior del registro es matemáticamente detectable.

Lo que este sistema **no** implementa, por diseño:

- **Ningún mecanismo de acceso remoto, intrusión o explotación de vulnerabilidades.** La
  consola manual (`consola_service.py`) solo ejecuta herramientas de reconocimiento pasivo/
  semi-activo (`nmap`, `whois`, `dig`, `httpx`, `curl`, `testssl.sh`, `nuclei` con plantillas
  de detección, `graphw00f`), listadas explícitamente en `CONSOLE_ALLOWED_BINARIES`. Esa lista
  no incluye frameworks de explotación ni herramientas de post-explotación.
- **Ningún agente/implante remoto.** El módulo de cese (`cese_service.py`) registra el
  **evento** de cese (quién, cuándo, con qué hash de verificación) como parte de la cadena de
  auditoría, pero no contiene ni invoca ningún mecanismo técnico de instalación/desinstalación
  remota. Si tal mecanismo existiera como pieza externa al sistema, se integraría únicamente
  aportando un comprobante que este módulo audita — el sistema nunca necesita conocer sus
  detalles técnicos.
- **`isp_service.py` es un placeholder** intencional: el enlace formal con proveedores de
  Internet queda pendiente de definición, tal como se especificó en el diseño original.

Todo lo demás — gestión de casos, carga de orden y alcance, motor de gating, auditoría con
cadena de hashes, pipeline de análisis con IA verificado contra NVD, cese como evento
auditable, notificación al imputado/defensor, cierre con hash de integridad — está
completamente implementado.

---

## Base legal

Código Procesal Penal de Misiones (Ley XIV N° 13), Título III, Capítulo IX (Arts. 284-287):

- **Art. 284** — orden general de obtención de evidencia digital, deber de colaboración de proveedores.
- **Art. 285** — adquisición remota mediante herramientas forenses, ejecutada por la SAIC; exige,
  bajo pena de nulidad: detalle de personal, duración, alcance y prórroga; cese y eliminación de
  la herramienta al cumplir el objetivo; notificación al imputado/defensor; fundamento de
  proporcionalidad, necesidad e idoneidad.
- **Art. 286** — hallazgo casual: todo nuevo objetivo, aunque sea del mismo imputado, requiere
  inclusión expresa en la orden antes de poder actuar sobre él.
- **Art. 287** — perfil digital encubierto (fuera del alcance de este sistema).

Marco general complementario: Const. Nac. Art. 18, Código Penal Art. 153 bis, Ley 25.520,
Ley 26.388/27.411 (Convenio de Budapest).

---

## Arquitectura

```
sharur-saic/
├── app/
│   ├── main.py                      # Entry point FastAPI
│   ├── core/
│   │   ├── config.py                 # Configuración centralizada (pydantic-settings)
│   │   ├── security.py               # JWT, hashing, control de roles
│   │   ├── logging.py                # Logging con redacción de datos sensibles
│   │   └── utils.py
│   ├── models/                       # SQLAlchemy: Caso, Orden, Dispositivo, Auditoria, Notificacion, Hallazgo
│   ├── schemas/                      # Pydantic: validación de entrada/salida de la API
│   ├── services/
│   │   ├── gating_service.py         # Motor de 3 validaciones: dispositivo / tiempo / operador
│   │   ├── auditoria_service.py      # Registro y verificación de cadena de hashes
│   │   ├── network_control.py        # Allow-list de red por caso (iptables)
│   │   ├── consola_service.py        # Consola manual, gateada, binarios en allow-list
│   │   ├── tools_service.py          # nmap/whois/dig/httpx/testssl/nuclei, gateados
│   │   ├── llm_service.py            # Interfaz evidence-first con Ollama
│   │   ├── cve_search_service.py     # Verificación de CVEs contra NVD
│   │   ├── analisis_ia_service.py    # Orquestador: herramienta → LLM → validación → Hallazgo
│   │   ├── orden_service.py          # Alcance, hallazgo casual (Art. 286)
│   │   ├── cese_service.py           # Registro de cese (evento auditable, sin mecanismo técnico)
│   │   ├── notificacion_service.py   # Notificación al imputado/defensor (Art. 285)
│   │   ├── caso_service.py           # Ciclo de vida del caso, cierre con hash final
│   │   └── isp_service.py            # Placeholder de enlace con ISP
│   ├── api/endpoints/                # Routers FastAPI
│   └── workers/                      # Tareas asíncronas Celery
├── tests/{unit,integration,e2e}/
├── alembic/                          # Migraciones de BD
├── docker/                           # Dockerfile + docker-compose
├── Modelfile                         # Definición del modelo custom "sharur-qwen" para Ollama
└── .github/workflows/                # CI (lint+test) y Deploy
```

---

## Flujo de uso

1. **Creación del caso** — `POST /api/v1/casos` — ID, número de causa, carátula, juzgado.
2. **Carga de la orden y su alcance** — `POST /api/v1/ordenes` (fundamentación de
   proporcionalidad/necesidad/idoneidad obligatoria) + `POST /api/v1/ordenes/{id}/personal`
   (personal autorizado) + `POST /api/v1/dispositivos` (cada dispositivo, con su sub-alcance de
   datos propio). **Nada se ejecuta hasta que esto está cargado.**
3. **Menú principal**:
   - **Análisis automatizado con IA** — `POST /api/v1/intervenciones/analisis-ia`: corre una
     herramienta gateada, pasa la evidencia al LLM, valida cada hallazgo propuesto contra la
     evidencia cruda (cita textual exacta) y contra NVD (CVE real), y persiste el resultado con
     nivel de confianza (`CONFIRMADA` / `PROBABLE` / `DESCARTADA`).
   - **Consola manual** — `POST /api/v1/intervenciones/consola`: ejecuta comandos de
     reconocimiento autorizados, dentro del perímetro de red allow-list del caso.
4. **Control continuo de alcance (gating)** — cada acción pasa por `gating_service.evaluar_gating()`
   antes de ejecutarse. Si falla dispositivo/tiempo/operador: rechazo automático, registro
   detallado del intento en auditoría (`ACCION_RECHAZADA_GATING`).
5. **Cese y notificación** — `POST /api/v1/dispositivos/{id}/cese` registra el cese por
   dispositivo (pueden ser momentos distintos); `notificacion_service` genera el registro de
   notificación al imputado/defensor con el contenido armado automáticamente desde los datos de
   la orden.
6. **Cierre** — `POST /api/v1/casos/{id}/cerrar`, manual (exige cese en todos los dispositivos) o
   forzado/automático (por expulsión). En ambos casos se genera el hash de integridad del
   reporte final.

---

## Auditoría con hash encadenado

Cada `EventoAuditoria` incluye el hash del evento anterior dentro del mismo caso. Alterar
cualquier campo de un evento pasado cambia su hash, lo cual invalida el `hash_evento_anterior`
de todos los eventos posteriores — propiedad detectable mediante:

```
GET /api/v1/casos/{caso_id}/auditoria/verificar
```

Ver `tests/unit/test_auditoria_service.py` para los casos de alteración de contenido y ruptura
de cadena.

**Nota técnica de robustez:** el hash se calcula sobre `timestamp_iso`, un string ISO-8601
persistido de forma independiente a la columna `timestamp` (`DateTime`). Esto evita falsos
positivos de "alteración" que surgirían si el motor de base de datos no preserva con fidelidad
perfecta el `tzinfo` de un `datetime` al recargarlo tras un `commit()` (se observó este
comportamiento en SQLite durante desarrollo). Por la misma razón, `gating_service.py` normaliza
cualquier `datetime` proveniente de la base con `core.utils.ensure_aware_utc()` antes de
compararlo contra `utc_now()`.

---

## Setup de desarrollo

Sharur SAIC necesita **tres cosas corriendo al mismo tiempo**: la base de datos (Postgres),
el modelo de IA local (Ollama, en su propia terminal) y la API (Sharur, en otra terminal).
La lógica es la misma que en el METATRON original (`ollama run metatron-qwen` en una terminal,
`python metatron.py` en otra) — acá se agrega Postgres porque reemplazamos SQLite/MariaDB por
un motor mas robusto para producción.

### 0. Requisitos previos

- Linux (probado sobre Debian/Ubuntu/Kali). Windows vía WSL2 también funciona.
- Python 3.12+
- Al menos 8.4 GB de RAM libre (el modelo base `qwen3.5-abliterated:9b` lo necesita; si tenés
  menos, usá la variante `4b`, ver paso 3).
- Git

### 1. Clonar el repositorio

```bash
git clone <URL_DEL_REPOSITORIO_SHARUR_SAIC>
cd sharur-saic
```

*(Reemplazá `<URL_DEL_REPOSITORIO_SHARUR_SAIC>` por la URL real una vez que subas este código a
tu propio repositorio Git — este proyecto se te entregó como código fuente, todavía no está
publicado en ningún remoto.)*

### 2. Crear el entorno virtual e instalar dependencias de Python

```bash
python3 -m venv venv
source venv/bin/activate          # en Windows/WSL2: venv\Scripts\activate

pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Instalar las herramientas de reconocimiento del sistema

Estas son las que `tools_service.py` y `consola_service.py` invocan por `subprocess`. Todas de
reconocimiento pasivo/semi-activo — ninguna de explotación:

```bash
sudo apt update
sudo apt install -y nmap whois dnsutils curl iptables
```

`httpx`, `nuclei` y `testssl.sh` (de ProjectDiscovery / Testssl) no vienen empaquetados en los
repos de apt; instalalos siguiendo la documentación oficial de cada proyecto, o usá la imagen
Docker (`docker/Dockerfile`), que ya los resuelve.

### 4. Instalar y levantar Ollama (el modelo de IA local)

**Paso a paso, igual que en METATRON:**

```bash
# 4.1 — Instalar Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 4.2 — Descargar el modelo base (requiere ~8.4 GB de RAM)
ollama pull huihui_ai/qwen3.5-abliterated:9b

# Si tu equipo tiene menos RAM, usá la variante mas liviana:
#   ollama pull huihui_ai/qwen3.5-abliterated:4b
# y despues editá la linea "FROM" del Modelfile para que apunte a esa variante.

# 4.3 — Crear el modelo custom "sharur-qwen" a partir del Modelfile del proyecto
#       (contexto de 16.384 tokens, temperatura 0.7, top_k 10, top_p 0.9 — ver Modelfile)
ollama create sharur-qwen -f Modelfile

# 4.4 — Confirmar que el modelo quedo creado
ollama list
# deberias ver "sharur-qwen" en el listado
```

**Terminal 1 — dejar el modelo cargado en memoria y corriendo:**

```bash
ollama run sharur-qwen
```

Esperá a ver el prompt `>>>`. Eso significa que el modelo esta cargado y listo. Dejá esta
terminal abierta en segundo plano — `llm_service.py` le habla por HTTP a
`http://localhost:11434` (ver `OLLAMA_URL` en la configuración), así que Ollama tiene que
seguir corriendo mientras uses Sharur.

### 5. Base de datos: instalar Postgres, crear la base y armar la `DATABASE_URL`

```bash
sudo apt install -y postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Crear el usuario y la base que va a usar Sharur
sudo -u postgres psql -c "CREATE USER sharur WITH PASSWORD 'elegí_una_contraseña_segura';"
sudo -u postgres psql -c "CREATE DATABASE sharur_saic OWNER sharur;"
```

La `DATABASE_URL` sigue el formato `postgresql+psycopg2://usuario:contraseña@host:puerto/nombre_de_base`.
Con lo creado arriba, en tu `.env` (ver paso 6) quedaría:

```
DATABASE_URL=postgresql+psycopg2://sharur:elegí_una_contraseña_segura@localhost:5432/sharur_saic
```

Si en cambio preferís levantar Postgres con Docker en vez de instalarlo en el sistema, usá
directamente `docker compose -f docker/docker-compose.yml up db` — ese servicio ya crea usuario
`sharur`/`sharur` y base `sharur_saic` automáticamente (ver variables `POSTGRES_*` en
`docker-compose.yml`), y no hace falta este paso manual.

### 6. Configurar el `.env`

```bash
cp .env.example .env
```

Editá `.env` y completá, como mínimo:

- **`DATABASE_URL`** — la que armaste en el paso 5.
- **`SECRET_KEY`** — la clave con la que se firman los tokens JWT (`app/core/security.py`).
  **Nunca** dejes el valor de ejemplo (`CHANGE_ME_...`). Generá una clave larga y aleatoria con:

  ```bash
  python3 -c "import secrets; print(secrets.token_hex(32))"
  ```

  Copiá el resultado como valor de `SECRET_KEY` en el `.env`.
- El resto de las variables (`OLLAMA_URL`, `OLLAMA_MODEL=sharur-qwen`, `NVD_API_KEY` opcional,
  `REDIS_URL`, etc.) ya tienen valores por defecto razonables para desarrollo local — revisalas
  en `.env.example`, pero no son obligatorias para levantar el sistema por primera vez.

### 7. Crear las tablas (migraciones de Alembic)

```bash
alembic upgrade head
```

Esto lee `alembic/env.py`, que a su vez toma `DATABASE_URL` de tu `.env`, y crea todas las
tablas (`casos`, `ordenes`, `dispositivos`, `eventos_auditoria`, etc.) en la base Postgres que
armaste en el paso 5.

### 8. Levantar Sharur

**Terminal 2 — con Ollama corriendo en la Terminal 1, en una terminal nueva:**

```bash
source venv/bin/activate     # si no esta ya activado en esta terminal
uvicorn app.main:app --reload
```

La API queda escuchando en `http://localhost:8000`. Podés confirmar que todo esta conectado
correctamente entrando a:

- `http://localhost:8000/health` — chequeo básico de que la API levantó.
- `http://localhost:8000/docs` — documentación interactiva (Swagger) de todos los endpoints.

**Login de desarrollo:** el sistema todavía no está conectado a un IdP institucional (ver
sección "Pendiente" al final), así que hay dos usuarios de prueba hardcodeados en
`app/api/endpoints/auth.py` para poder probar la API de punta a punta:

| Usuario     | Contraseña    | Rol         |
|-------------|---------------|-------------|
| `admin`     | `admin123`    | `admin`     |
| `operador1` | `operador123` | `operador`  |

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=operador1&password=operador123"
```

Devuelve un `access_token` JWT que se usa como `Authorization: Bearer <token>` en el resto de
los endpoints. **Estas credenciales son solo para desarrollo — nunca las dejes activas en un
despliegue real** (ver nota en el propio archivo `auth.py`).

**Resumen visual (dos terminales, igual que METATRON):**

```
Terminal 1                          Terminal 2
-----------                         -----------
$ ollama run sharur-qwen            $ source venv/bin/activate
>>> (modelo cargado, dejar          $ uvicorn app.main:app --reload
     corriendo en segundo plano)    INFO: Uvicorn running on http://0.0.0.0:8000
```

### 9. (Opcional) Worker de Celery, si vas a probar tareas asíncronas

En una **tercera terminal**, con el entorno virtual activado:

```bash
celery -A app.workers.celery_app worker --loglevel=info
```

Esto requiere Redis corriendo (`sudo apt install redis-server && sudo systemctl start redis`,
o `docker compose -f docker/docker-compose.yml up redis`).

### Todo junto con Docker (alternativa a los pasos 3, 5, 7, 8, 9)

Si no querés instalar Postgres/Redis/herramientas de reconocimiento a mano en tu sistema, Docker
Compose levanta la API, Postgres, Redis, el worker y el beat de Celery en un solo comando —
**pero Ollama seguís levantándolo aparte, en tu Terminal 1, con los pasos del punto 4**, porque
corre mejor con acceso directo a la GPU/CPU del host que dentro de un contenedor:

```bash
cp .env.example .env
# completá DATABASE_URL, SECRET_KEY, etc. igual que en el paso 6

docker compose -f docker/docker-compose.yml up --build
```

### Tests

```bash
pytest tests/unit -v
```

Los tests unitarios usan una base SQLite en memoria (ver `tests/conftest.py`), así que no
necesitan que Postgres ni Ollama estén corriendo.

---

## Roles

Solo existen dos roles de login. Jueces, fiscales y defensores **no** son cuentas del
sistema: su intervención es el proceso judicial de siempre (orden firmada en papel/expediente),
y el operador es quien carga esos datos ya resueltos (número de orden, juez firmante,
fundamentos, datos del imputado/defensor) como texto dentro de la orden — ver
`schemas/orden.py`, donde `juez_firmante`, `defensor_nombre`, etc. son campos `string`, no
cuentas de usuario.

| Rol        | Permisos                                                                 |
|------------|---------------------------------------------------------------------------|
| `operador` | Control funcional total: casos, órdenes, dispositivos, intervenciones (análisis IA, consola), cese, notificación, consulta de auditoría |
| `admin`    | Igual que `operador` a nivel de API, más gestión de cuentas de operadores (fuera de este repo, vía IdP institucional) |

El rol de API es una primera barrera (¿esta cuenta puede usar el sistema?); la autorización
real y granular por caso/dispositivo la resuelve `gating_service.py` contra la tabla
`PersonalAutorizado` de cada orden (¿este operador específico está habilitado para actuar sobre
este dispositivo específico, ahora?). Un operador con cuenta válida en el sistema puede seguir
siendo rechazado por el gating si no figura como personal autorizado de la orden correspondiente.

---

## Pendiente / fuera de este alcance

- Integración real con IdP institucional (LDAP/AD) en `app/api/endpoints/auth.py` — hoy hay un
  placeholder en memoria para desarrollo.
- `isp_service.py` — enlace formal con proveedores (Art. 284), pendiente de definición del canal.
- Cualquier mecanismo técnico de acceso remoto a un dispositivo específico — deliberadamente
  fuera del alcance de este repositorio (ver sección de límite arriba).
