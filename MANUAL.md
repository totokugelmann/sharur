# Manual de despliegue · Sharur v2.0.1

Proyecto Integrador Final · Universidad de la Cuenca del Plata · Ingeniería en Sistemas de Información

Autor: Kugelmann, Tomás Ezequiel · Repositorio: https://github.com/totokugelmann/sharur

Este manual permite que una persona que no participó del desarrollo instale y ejecute Sharur en una máquina limpia, siguiendo los pasos en orden y sin suplir ninguno. Cada bloque de comandos se copia tal cual. Los comandos se escriben para distribuciones basadas en Debian (sección 2), las únicas sobre las que se verificó este procedimiento.

---

## 1. Propósito y versión

Sharur es un sistema de línea de comandos para la Secretaría de Apoyo para Investigaciones Complejas (SAIC) del Poder Judicial de Misiones. Registra cada acción de una intervención técnica en una cadena de auditoría con hash SHA-256 encadenado, de modo que cualquier alteración posterior de un registro es detectable, y asiste al perito en la adquisición estática de evidencia y el análisis de red.

**Versión:** etiqueta `v2.0.1`. Contiene el mismo código que `v2.0` (15/11/2026) y agrega este manual, la declaración de IA del README en cinco campos y las versiones exactas de las dependencias.

**Alcance de esta versión:**

| Caso de uso | Requisito |
|---|---|
| Crear un caso con expediente y oficio únicos (rechaza duplicados) | RF-01 |
| Registrar cada acción en la cadena de auditoría encadenada | RF-08, RNF-01 |
| Detectar equipos en la red local con nmap (cuatro perfiles), arp-scan o netdiscover | RF-06 |
| Escanear puertos y servicios de un objetivo con nmap (tres perfiles) | RF-06 |
| Analizar la salida con el modelo de IA local y validar los CVE contra la NVD; nivel de riesgo global determinista | RF-13, RF-16 |
| Ejecutar comandos en la consola auditada, con lista negra y validación del objetivo | RF-07 (reformulado), RNF-03 |
| Consultar los últimos 25 eventos de auditoría | RF-08 |
| Exportar el informe del caso en HTML (o PDF) con su SHA-256 | RF-15 |
| Cerrar el caso con un hash de reporte final | RF-12 |

Fuera de esta versión, y declarados en la hoja de ruta del informe (Capítulo XI): carga de orden judicial y personal autorizado, gating por dispositivo y ventana, cese por dispositivo y hallazgo casual.

---

## 2. Requisitos previos

Sistema operativo: distribuciones Linux **basadas en Debian** (Debian, Ubuntu, Kali), 64 bits. Verificado en **Ubuntu 24.04 LTS**, con las versiones de la tabla, y en **Kali Linux rolling**, donde nmap, arp-scan y netdiscover vienen preinstalados.

| Componente | Versión de referencia | Uso | ¿Obligatorio? |
|---|---|---|---|
| Python | 3.12.3 (compatible con 3.13) | Lenguaje del sistema | Sí |
| python3-venv | el de la distribución | Entorno virtual | Sí |
| PostgreSQL | 16 (mínimo 14) | Base de datos | Sí |
| git | 2.43 | Obtención del código | Sí |
| nmap | 7.94 | Detección y escaneo | Sí |
| arp-scan | 1.10.0 | Detección en red local | Sí |
| netdiscover | 0.10 | Detección en red local | Sí |
| Ollama | 0.x vigente | Análisis asistido por IA | No |
| weasyprint | 62 o superior | Informe en PDF | No |

Hardware mínimo: 2 núcleos, 4 GB de RAM y 2 GB libres en disco. Con IA: 8 GB de RAM para el modelo de 4B. Se necesita una cuenta con permisos de `sudo`.

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip postgresql postgresql-contrib nmap arp-scan netdiscover
sudo systemctl enable --now postgresql
```

Verificación:

```bash
python3 --version      # Python 3.12.x
psql --version         # psql (PostgreSQL) 16.x
nmap --version | head -1
```

---

## 3. Obtención del código

```bash
git clone https://github.com/totokugelmann/sharur.git
cd sharur
git checkout v2.0.1
git describe --tags    # debe mostrar: v2.0.1
```

---

## 4. Configuración

```bash
cp .env.example .env
```

No hace falta editar nada: el `DATABASE_URL` de ejemplo apunta a la base que crea el paso 5. Ninguna variable contiene credenciales reales.

| Variable | Significado | Valor de ejemplo |
|---|---|---|
| `APP_ENV` | Entorno de ejecución | `development` |
| `DATABASE_URL` | Conexión a PostgreSQL | `postgresql+psycopg2://sharur_user:sharur_pass@localhost:5432/sharur_db` |
| `OLLAMA_URL` | Endpoint del modelo local | `http://localhost:11434/api/chat` |
| `OLLAMA_MODEL` | Nombre del modelo local | `sharur-qwen` |
| `OLLAMA_TIMEOUT` | Tiempo máximo de respuesta del modelo, en segundos | `600` |
| `NVD_API_URL` | API de la base nacional de vulnerabilidades | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| `NVD_API_KEY` | Clave opcional de la NVD (amplía el límite de consultas) | vacío |
| `NVD_CACHE_PATH`, `NVD_CACHE_TTL_HORAS` | Caché local de consultas a la NVD | `logs/nvd_cache.json`, `24` |
| `REPORTS_DIR` | Carpeta de los informes exportados | `./reports` |
| `LOG_LEVEL`, `LOG_DIR` | Nivel y carpeta de registros de la aplicación | `INFO`, `./logs` |
| `EVIDENCE_STORAGE_DIR` | Carpeta reservada para evidencia | `./evidence_storage` |
| `SECRET_KEY`, `ALGORITHM`, `ACCESS_TOKEN_EXPIRE_MINUTES`, `REDIS_URL`, `CELERY_*`, `NETWORK_CONTROL_BACKEND` | Variables heredadas de una arquitectura descartada; esta versión no las usa | valores del ejemplo |

Las listas de control de la consola no se configuran en `.env`: están en `app/core/config.py` (`CONSOLE_BANNED_BINARIES`, 11 binarios destructivos, y `CONSOLE_BANNED_PATTERNS`, 12 patrones de redirección, encadenado e inyección).

---

## 5. Base de datos

### 5.1 Crear la base y el usuario

El repositorio incluye un script idempotente: borra lo anterior y deja siempre el mismo estado (base `sharur_db`, usuario `sharur_user`, permisos sobre el schema `public`).

```bash
sudo -u postgres psql -f scripts/init_db.sql
```

Debe terminar con `Sharur: base sharur_db y usuario sharur_user listos.`

### 5.2 Esquema (migraciones)

El esquema se crea automáticamente al arrancar el sistema: `sharur_cli.py` ejecuta `Base.metadata.create_all()` sobre los modelos de `app/models/` y crea seis tablas (`casos`, `eventos_auditoria`, `ordenes`, `personal_autorizado`, `dispositivos`, `hallazgos`). Esta versión no usa archivos de migración separados: ante un cambio de esquema, se vuelve a ejecutar el paso 5.1.

### 5.3 Datos de prueba

El sistema trabaja exclusivamente con **datos sintéticos**. El escenario se genera durante el recorrido del paso 8:

| Campo | Valor del escenario |
|---|---|
| Número de expediente | `EXP-DEMO-001/2026` |
| Número de oficio | `OF-DEMO-001` |
| Operador | `operador.demo` |
| Objetivo autorizado | `127.0.0.1` (o un equipo de una red de laboratorio aislada) |

Para repetir el recorrido desde cero se vuelve a ejecutar el paso 5.1.

---

## 6. Instalación de dependencias y ejecución

### 6.1 Entorno virtual y dependencias

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` fija la versión exacta de cada dependencia: SQLAlchemy 2.1.8, pydantic 2.14.3, pydantic-settings 2.16.3, python-dotenv 1.2.4, rich 15.0.0, requests 2.34.2, psycopg2-binary 2.9.13 y pytest 9.2.0.

### 6.2 Modelo de IA local (opcional)

Sólo para el análisis de vulnerabilidades y el modo «Enriquecido». Sin él, el sistema funciona y el análisis informa sólo los CVE hallados por producto y versión en la NVD.

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull huihui_ai/qwen3.5-abliterated:4b
ollama create sharur-qwen -f Modelfile
ollama list    # debe listar sharur-qwen
```

El servicio queda escuchando en `localhost:11434`. Para el PDF nativo del informe, opcionalmente: `sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0 && pip install weasyprint`.

### 6.3 Arranque

Las herramientas de red necesitan privilegios de administrador, por lo que el sistema se arranca con `sudo` usando **el intérprete del entorno virtual**:

```bash
sudo venv/bin/python sharur_cli.py
```

Sharur es una aplicación de terminal: no abre ningún puerto. Se conecta a PostgreSQL en `localhost:5432` y, si está instalado, a Ollama en `localhost:11434`.

### 6.4 Detención

`[6] Salir` en el menú del caso (cierra el caso) y `[2] Salir` en el menú principal. `Ctrl+C` dentro de la consola aborta el comando en curso sin cerrar Sharur.

---

## 7. Usuario de demostración

Esta versión no tiene inicio de sesión: el operador se identifica por su nombre al crear el caso, y ese nombre queda en cada evento de la cadena.

| Usuario | Contraseña | Rol |
|---|---|---|
| `operador.demo` | no aplica (sin autenticación en v2.0.1) | Operador técnico |

La base usa el usuario de prueba `sharur_user` con contraseña `sharur_pass`, válido sólo en la máquina local. Ninguno de estos datos es una credencial real.

---

## 8. Verificación

### 8.1 Prueba de humo

`sudo venv/bin/python sharur_cli.py` muestra el banner de Sharur y el panel **SHARUR SAIC · Menú principal** con `[1] Crear caso` y `[2] Salir`, sin mensajes de error.

### 8.2 Recorrido de los casos de uso

1. **Crear caso (RF-01).** `1` → `EXP-DEMO-001/2026`, `OF-DEMO-001`, `operador.demo`. Resultado: `Caso creado — expediente EXP-DEMO-001/2026` y el menú del caso con seis opciones.
2. **Detectar equipos (RF-06).** `1` → `2` (arp-scan) → `1` (Básico). Resultado: panel con los equipos, la duración y el `Hash evidencia`. `ENTER` y `4` para volver.
3. **Objetivo y análisis (RF-06, RF-13, RF-16).** `2` → `127.0.0.1` → `2` (rápido). Resultado: panel de nmap con los puertos y, a continuación, el análisis: con Ollama, los hallazgos clasificados por confianza; sin Ollama o sin Internet, los avisos `El modelo local no respondió` o `La NVD no respondió`. Siempre cierra con **RIESGO GLOBAL DEL CASO**. `ENTER`.
4. **Consola auditada (RF-07, RNF-03).** `3` → objetivo `127.0.0.1`. Ejecutar `nmap -sn 127.0.0.1` (corre); `nmap -sn 10.0.0.5` (rechazo: `Intento de atacar a 10.0.0.5`); `rm -rf /tmp/x` (rechazo: patrón prohibido). `salir`.
5. **Auditoría (RF-08).** `4`. Resultado: tabla con los eventos (`caso_creado`, `accion_autorizada`, `hallazgo_ia_propuesto`, `accion_rechazada_gating`), el más reciente primero. `ENTER`.
6. **Informe (RF-15).** `5` → `1` (HTML). Resultado: `Informe generado: ./reports/informe_caso_1_<fecha>.html` y su SHA-256. `ENTER`.
7. **Cerrar (RF-12).** `6` → motivo `Fin de la demostración` → `n` a la pregunta de exportar.
8. **Duplicado (RF-01).** `1` con `EXP-DEMO-001/2026` y `OF-DEMO-002`. Resultado: `Ya existe un caso con el expediente 'EXP-DEMO-001/2026'.` → `2` para salir.
9. **Comprobación en la base:**

```bash
sudo -u postgres psql -d sharur_db -c "SELECT numero_causa, estado, hash_reporte_final FROM casos;"
sudo -u postgres psql -d sharur_db -c "SELECT secuencia, tipo_evento, left(hash_evento,16) AS hash, left(hash_evento_anterior,16) AS anterior FROM eventos_auditoria ORDER BY secuencia;"
```

Resultado: el caso figura `CERRADO_MANUAL` con un hash final de 64 caracteres, y la columna `anterior` de cada evento coincide con el `hash` del evento previo.

---

## 9. Pruebas automatizadas

```bash
source venv/bin/activate
pytest -q
```

Resultado esperado: `51 passed`. Cubren la cadena de auditoría, el cierre del caso, el parser de nmap, la validación de citas, la búsqueda de CVE, el cálculo de riesgo, el pipeline de análisis, la exportación del informe y las importaciones de todos los módulos. No requieren PostgreSQL, Ollama ni Internet. El canal de integración continua (`.github/workflows/ci.yml`) ejecuta la misma batería con Python 3.12 en cada push a `main` o `develop` y en cada etiqueta `v*`: https://github.com/totokugelmann/sharur/actions

---

## 10. Problemas frecuentes

| Síntoma | Causa | Solución |
|---|---|---|
| `Peer authentication failed for user "postgres"` | `psql -U postgres` desde el usuario propio | Usar `sudo -u postgres psql -f scripts/init_db.sql` |
| `template database has a collation version mismatch` | Kali/Debian rolling tras actualizar glibc | El script del paso 5.1 lo corrige; volver a ejecutarlo |
| `permission denied for schema public` | PostgreSQL 15 o superior | Volver a ejecutar el paso 5.1, que otorga el permiso conectado a `sharur_db` |
| `error: externally-managed-environment` | `pip` fuera del entorno virtual | `source venv/bin/activate` antes de `pip install` |
| `ModuleNotFoundError` al usar `sudo` | `sudo python` usa el Python del sistema | Arrancar con `sudo venv/bin/python sharur_cli.py` |
| `Binario 'arp-scan' no disponible` | Herramienta sin instalar | `sudo apt install -y arp-scan` (ídem nmap y netdiscover) |
| `No se encontraron otros hosts. Posible AP Isolation.` | Red inalámbrica con aislamiento de clientes | Usar el perfil Profundo de nmap o una red cableada de laboratorio |
| `El modelo local no respondió` | Ollama apagado o modelo sin crear | `ollama serve` y paso 6.2 |
| `La NVD no respondió` | Sin Internet o límite de consultas de la NVD | Reintentar más tarde o cargar `NVD_API_KEY` en `.env` |
| `COMANDO BLOQUEADO: El comando debe incluir el target` | La consola exige el objetivo autorizado en cada línea | Escribir la IP del objetivo en el comando |
| El informe sale en HTML aunque se pidió PDF | weasyprint sin instalar | Instalarlo (paso 6.2) o imprimir el HTML a PDF |

---

## 11. Terceros e inteligencia artificial

**Componentes de terceros.** Versión, licencia y motivo: Capítulo IX, apartado IX.4, del informe final. Resumen: Python (PSF), PostgreSQL (PostgreSQL License), SQLAlchemy, pydantic, pydantic-settings, rich y pytest (MIT), requests (Apache-2.0), python-dotenv (BSD-3-Clause), psycopg2-binary (LGPL-3.0 con excepciones), nmap (Nmap Public Source License), arp-scan (GPL-3.0), netdiscover (GPL-2.0), Ollama (MIT) y weasyprint (BSD-3-Clause).

**Declaración de uso de inteligencia artificial sobre el código.** La misma tabla figura en la sección 7 del README y en la Bitácora Individual.

| Herramienta | Función | Pieza (commit) | Fecha | Verificación posterior del autor |
|---|---|---|---|---|
| Claude (Anthropic) | Canal de integración continua, pruebas de la cadena y `pytest.ini` | 9b8d5ba | 02/10/2026 | `pytest` local 5/5 y corrida exitosa en GitHub Actions |
| Claude (Anthropic) | README de la versión v1 | 6102e4b | 02/10/2026 | Clonado y recorrido en máquina virtual |
| Claude Code (Claude Opus 4.8) | Búsqueda de CVE por producto y versión, riesgo global, exportación del informe y limpieza | 8462e9e | 14/11/2026 | Batería de pruebas y recorrido manual del análisis |
| Claude Code (Claude Opus 4.8) | Registro del CPE coincidente; opción «Volver» del informe; corrección de la exportación | 02bd4ca, 24fe6bc, 7e7c78d | 14/11/2026 | Batería de pruebas y exportación manual del informe |
| Claude Code (Claude Opus 4.8) | Interfaz de consola con rich y corrección del menú de exportación | ada8a12 | 15/11/2026 | 51/51 pruebas y recorrido completo en consola |
| Claude Code (Claude Opus 4.8) | README de la v2.0 (limitaciones y alcance pericial) | 04bbd87 | 15/11/2026 | Lectura completa y recorrido de la instalación |
| Claude (Anthropic) | Este manual, la declaración del README y las versiones fijadas | etiqueta v2.0.1 | 15/11/2026 | Recorrido completo del manual en máquina limpia |
