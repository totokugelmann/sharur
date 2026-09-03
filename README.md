# Sharur SAIC

Sharur es un sistema para gestionar intervenciones técnicas sobre dispositivos digitales
dentro de una causa judicial: se carga el caso, se registra la orden que la autoriza junto con
los dispositivos y el alcance permitido, y a partir de ahí cada acción que se ejecuta (un
escaneo, un comando de consola, un cese) queda validada contra ese alcance y registrada en una
auditoría que no se puede alterar sin que quede evidencia de la alteración.

Nace como una reescritura del framework original *Sharur* (reconocimiento de red y análisis de
APKs, con un modelo de IA local que solo puede señalar hallazgos que cite textualmente de la
evidencia real, nunca inventarlos), reorganizado como un servicio con base de datos propia,
API HTTP y un CLI interactivo.

## Qué hace y qué no hace

La idea central del sistema es simple: controla **cuándo, sobre qué y por cuánto tiempo** se
puede actuar. Eso es lo que lo hace confiable como registro — cada acción se valida contra un
alcance autorizado explícito, y cada evento de auditoría incluye el hash del evento anterior,
así que alterar un registro pasado rompe visiblemente la cadena de todos los que vinieron
después.

Lo que el sistema deliberadamente no incluye:

- No tiene ningún mecanismo de acceso remoto, intrusión ni explotación de vulnerabilidades. La
  consola manual solo puede correr herramientas de reconocimiento (nmap, whois, dig, httpx,
  curl, testssl, nuclei con plantillas de detección, graphw00f), todas listadas explícitamente
  en la configuración. No hay forma de invocar nada fuera de esa lista.
- No implementa ningún agente ni implante remoto. El módulo de cese registra el evento de cese
  — quién, cuándo, con qué comprobante — como parte de la auditoría, pero no contiene ningún
  mecanismo técnico de instalación o desinstalación. Si algo así existiera como pieza externa al
  sistema, lo único que haría este módulo es auditar el comprobante que le entreguen, sin
  necesitar saber cómo se logró.
- El enlace con proveedores de Internet (`isp_service.py`) es un placeholder a propósito:
  todavía no está definido el canal formal para esas solicitudes, así que el módulo existe como
  punto de extensión pero no hace nada por ahora.

Todo lo demás —gestión de casos, carga de orden y alcance, el motor que valida cada acción,
auditoría con cadena de hashes, el análisis con IA verificado contra vulnerabilidades reales,
cese, notificación, cierre de caso con hash final— está implementado y funcionando.

## Cómo está organizado

sharur-saic/
├── app/
│ ├── main.py # arranque de la API
│ ├── core/
│ │ ├── config.py # configuración centralizada
│ │ ├── security.py # JWT, hashing, control de roles
│ │ ├── logging.py # logging con redacción de datos sensibles
│ │ └── utils.py
│ ├── models/ # Caso, Orden, Dispositivo, Auditoria, Notificacion, Hallazgo
│ ├── schemas/ # validación de entrada/salida de la API
│ ├── services/
│ │ ├── gating_service.py # valida dispositivo / tiempo / operador en cada acción
│ │ ├── auditoria_service.py # registro y verificación de la cadena de hashes
│ │ ├── network_control.py # allow-list de red por caso (iptables)
│ │ ├── consola_service.py # consola manual, gateada, binarios en lista blanca
│ │ ├── tools_service.py # nmap/whois/dig/httpx/testssl/nuclei, gateados
│ │ ├── llm_service.py # interfaz con el modelo local (Ollama)
│ │ ├── cve_search_service.py # verificación de CVEs contra NVD
│ │ ├── analisis_ia_service.py # une herramienta, LLM y validación en un solo pipeline
│ │ ├── orden_service.py # alcance de la orden, hallazgo casual
│ │ ├── cese_service.py # registro de cese como evento auditable
│ │ ├── notificacion_service.py # notificación al imputado/defensor
│ │ ├── caso_service.py # ciclo de vida del caso, cierre con hash final
│ │ └── isp_service.py # placeholder de enlace con proveedores
│ ├── api/endpoints/ # rutas de la API
│ ├── cli/ # el CLI interactivo (ui.py, sesion.py, consola.py, menu_analisis.py)
│ └── workers/ # tareas asíncronas con Celery
├── sharur_cli.py # entrada del CLI
├── tests/{unit,integration,e2e}/
├── alembic/ # migraciones de base de datos
├── docker/ # Dockerfile y docker-compose
├── Modelfile # define el modelo "sharur-qwen" para Ollama
└── .github/workflows/ # CI y deploy


## Poniéndolo a andar

Sharur necesita tres cosas corriendo al mismo tiempo: la base de datos, el modelo de IA local
(en su propia terminal) y la API o el CLI (en otra). Vamos paso a paso.

### Lo que necesitás antes de empezar

Linux (se probó sobre Debian, Ubuntu y Kali; Windows funciona vía WSL2), Python 3.12 o más
nuevo, Git, y al menos 8.4 GB de RAM libres si vas a usar el modelo de IA completo (hay una
variante más liviana si tu máquina tiene menos memoria, lo vemos más abajo).

### Traer el proyecto

```bash
git clone https://github.com/totokugelmann/sharur.git
cd sharur
```

### Preparar el entorno de Python

```bash
python3 -m venv venv
source venv/bin/activate          # en Windows/WSL2: venv\Scripts\activate

pip install --upgrade pip
pip install -r requirements.txt
```

Cada vez que abras una terminal nueva para trabajar en el proyecto vas a necesitar activar el
entorno de nuevo con `source venv/bin/activate` antes de correr cualquier cosa — si te aparece
un error de módulo no encontrado, lo más probable es que te hayas olvidado este paso.

### Instalar las herramientas de reconocimiento

Son las que la consola y el menú de análisis terminan invocando:

```bash
sudo apt update
sudo apt install -y nmap whois dnsutils curl iptables
```

`httpx`, `nuclei` y `testssl.sh` no vienen empaquetados en los repositorios de apt — instalalos
siguiendo la documentación de cada proyecto, o usá la imagen Docker del repositorio, que ya los
trae resueltos.

### Levantar el modelo de IA local

```bash
curl -fsSL https://ollama.com/install.sh | sh

ollama pull huihui_ai/qwen3.5-abliterated:9b
```

Si tu máquina tiene poca RAM, hay una variante más chica:

```bash
ollama pull huihui_ai/qwen3.5-abliterated:4b
```

En ese caso editá la línea `FROM` del archivo `Modelfile` en la raíz del proyecto para que
apunte a esa variante antes del siguiente paso.

```bash
ollama create sharur-qwen -f Modelfile
ollama list
```

Deberías ver `sharur-qwen` en el listado. Ahora dejalo corriendo en una terminal aparte, que va
a quedar reservada para esto mientras trabajás:

```bash
ollama run sharur-qwen
```

Cuando veas el prompt `>>>`, el modelo está cargado y esperando. No cierres esta terminal.

### Base de datos

```bash
sudo apt install -y postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql

sudo -u postgres psql -c "CREATE USER sharur WITH PASSWORD 'elegí_una_contraseña_segura';"
sudo -u postgres psql -c "CREATE DATABASE sharur_saic OWNER sharur;"
```

Con eso, la URL de conexión que vas a usar en el siguiente paso queda:

postgresql+psycopg2://sharur:elegí_una_contraseña_segura@localhost:5432/sharur_saic


Si preferís levantar Postgres con Docker en vez de instalarlo directo en tu sistema, `docker
compose -f docker/docker-compose.yml up db` crea usuario y base automáticamente, y podés saltear
este paso manual.

### Configuración

```bash
cp .env.example .env
```

Abrí `.env` y completá al menos:

- `DATABASE_URL` con la cadena que armaste arriba.
- `SECRET_KEY`, la clave con la que se firman las sesiones. Nunca dejes el valor de ejemplo —
  generá una nueva con:

```bash
  python3 -c "import secrets; print(secrets.token_hex(32))"
```

El resto de las variables (`OLLAMA_URL`, `OLLAMA_MODEL`, `REDIS_URL`, etc.) ya vienen con
valores razonables para trabajar en desarrollo, así que no hace falta tocarlas para arrancar por
primera vez.

### Crear las tablas

```bash
alembic upgrade head
```

Esto crea todas las tablas del sistema en la base que acabás de armar. Si más adelante cambiás
algún modelo, generás la migración correspondiente con `alembic revision --autogenerate -m
"descripción"` y la aplicás de la misma forma.

### Arrancar la API

En una segunda terminal (la primera queda ocupada por Ollama):

```bash
source venv/bin/activate
uvicorn app.main:app --reload
```

Con eso arriba, `http://localhost:8000/health` te confirma que la API está viva, y
`http://localhost:8000/docs` te da una interfaz donde probar cada endpoint sin tener que armar
requests a mano.

Para entrar necesitás loguearte. Todavía no hay conexión con un sistema de usuarios
institucional, así que por ahora hay dos cuentas de prueba:

| Usuario     | Contraseña    | Rol         |
|-------------|---------------|-------------|
| `admin`     | `admin123`    | `admin`     |
| `operador1` | `operador123` | `operador`  |

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=operador1&password=operador123"
```

Te devuelve un token que usás como `Authorization: Bearer <token>` en el resto de los pedidos.
Estas credenciales son solo para desarrollo, nunca deberían quedar activas en un despliegue
real.

### Worker de tareas asíncronas (opcional)

Si vas a probar los escaneos largos que corren en segundo plano, necesitás Redis y un worker de
Celery corriendo, en una tercera terminal:

```bash
sudo apt install redis-server
sudo systemctl start redis
celery -A app.workers.celery_app worker --loglevel=info
```

### Todo junto con Docker

Si no querés instalar Postgres, Redis y las herramientas de reconocimiento a mano, Docker
Compose levanta la API, la base, Redis y los workers en un solo comando. Ollama seguís
levantándolo aparte, en su propia terminal, porque anda mejor con acceso directo al hardware del
equipo que dentro de un contenedor:

```bash
cp .env.example .env
docker compose -f docker/docker-compose.yml up --build
```

### Correr los tests

```bash
pytest tests/unit -v
```

Usan una base en memoria, así que no necesitás tener Postgres ni Ollama corriendo para
ejecutarlos.

## Usando el CLI

Además de la API, el proyecto tiene un CLI de terminal que va guiando paso a paso — pensado
para que no tengas que armar cada request a mano. No duplica ninguna lógica: llama exactamente
a los mismos servicios que usa la API, así que todo lo que hagas desde acá queda validado y
auditado de la misma forma.

```bash
python sharur_cli.py
```

El flujo empieza pidiéndote tu usuario, que tiene que coincidir con el personal autorizado de la
orden que vayas a operar — si no coincide, cada acción que intentes va a ser rechazada. Después
elegís o creás un caso, y si el caso no tiene una orden cargada, te la pide completa: los
fundamentos que justifican la medida, la ventana temporal durante la cual está vigente, los
datos del imputado y su defensor, quién más está autorizado a operar, y los dispositivos dentro
del alcance.

Cada dispositivo se carga con un identificador descriptivo — puede ser el modelo, un IMEI, un
dominio, o una IP si es fija — y opcionalmente un rango de red, útil cuando la IP del
dispositivo es dinámica y no se conoce de antemano, así que hay que escanear el rango completo
para localizarlo. El sistema no intenta adivinar automáticamente cuál de los equipos que
aparezcan en ese rango es el dispositivo autorizado — eso depende de cosas como MAC o hostname,
que se pueden falsear, así que esa verificación queda en tus manos, revisando la evidencia
después de cada escaneo.

Con el dispositivo elegido, entrás al menú principal:
nmap
whois
dig
httpx
testssl
nuclei
Ver hallazgos registrados en este dispositivo
Ver auditoría del caso
Ejecutar cese sobre este dispositivo
Cambiar de dispositivo
Consola
Salir

Al elegir cualquiera de las primeras seis opciones, te pregunta el objetivo antes de correr
nada — te sugiere el identificador o el rango del dispositivo, pero podés escribir otro valor.
Si elegís nmap, además te pregunta qué perfil de escaneo usar: default, rápido, completo, o
sigiloso. Cuando el resultado es exitoso, te ofrece mandar esa evidencia al modelo de IA para
que sugiera vulnerabilidades aplicables, verificadas contra la base de datos real de CVEs antes
de guardarse como hallazgo.

La consola, al final de la lista, se siente como abrir una terminal en tu propia máquina —
escribís el comando, ves el resultado — con la diferencia de que solo podés invocar los
binarios de reconocimiento permitidos, nunca un shell libre, y cada línea que ejecutás queda
registrada.

sharur(192.0.2.10)> nmap -sV -F 192.0.2.10
sharur(192.0.2.10)> whois example.com
sharur(192.0.2.10)> salir


Al terminar la sesión, el CLI te ofrece cerrar el caso. Para eso exige que todos los
dispositivos tengan su cese ya ejecutado, o si preferís, podés dejarlo abierto y retomarlo
después.

## Quién puede hacer qué

Solo existen dos roles con cuenta en el sistema. Jueces, fiscales y defensores no son usuarios
de Sharur — su intervención sigue siendo el proceso judicial de siempre, y es el operador quien
carga esos datos ya resueltos (número de orden, quién la firmó, los fundamentos) como texto
dentro del sistema.

El rol `operador` tiene control funcional completo: casos, órdenes, dispositivos,
intervenciones, cese, notificación, y consulta de auditoría. El rol `admin` tiene lo mismo, más
la gestión de cuentas de otros operadores, algo que en un despliegue real vendría de un sistema
de usuarios institucional en vez de manejarse acá.

Tener una cuenta válida es solo la primera barrera. La autorización real, la que importa, la
resuelve el motor de validación contra la lista de personal autorizado de cada orden específica
— un operador con cuenta activa en el sistema puede seguir siendo rechazado si no figura como
autorizado en la orden sobre la que está intentando actuar.

## Cómo funciona la auditoría

Cada evento que se registra incluye el hash del evento inmediatamente anterior dentro del mismo
caso. Si alguien intenta alterar un registro pasado —cambiar una descripción, borrar un
intento fallido— el hash de ese evento cambia, y con él deja de coincidir con lo que el
siguiente evento tiene guardado como referencia. La ruptura queda visible apenas se recalcula la
cadena:

GET /api/v1/casos/{caso_id}/auditoria/verificar


o desde la opción 8 del menú del CLI.

Un detalle técnico que vale la pena mencionar: el hash se calcula sobre una marca de tiempo
guardada como texto, separada de la columna de fecha propiamente dicha. Esto es porque durante
el desarrollo se encontró que algunos motores de base de datos no siempre conservan con
exactitud la información de zona horaria al recargar un dato después de guardarlo, lo cual
podía generar falsas alarmas de alteración sobre registros que en realidad nunca se tocaron.
Guardar el texto exacto que se usó para el cálculo evita ese problema.

## Lo que todavía falta

- Conectar el login a un sistema de usuarios institucional real, en vez de las dos cuentas de
  desarrollo que hay hoy.
- Definir el canal formal de comunicación con proveedores de Internet — el módulo existe como
  punto de extensión, pero no hace nada todavía.
- Cualquier mecanismo técnico de acceso remoto a un dispositivo específico queda,
  deliberadamente, fuera de este repositorio.
