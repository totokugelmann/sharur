# Sharur SAIC

## 1. Identificación

| | |
|---|---|
| **Proyecto** | Sharur — framework de adquisición estática de evidencia y análisis de red para la Secretaría de Apoyo para Investigaciones Complejas (SAIC) |
| **Autor** | Kugelmann, Tomás Ezequiel |
| **Comisión** | A · Sede Posadas |
| **Carrera** | Ingeniería en Sistemas de Información · Universidad de la Cuenca del Plata |
| **Actividad** | Proyecto Integrador Final · Actividad de Evaluación N.º 2 |
| **Etiqueta** | `v1` — prototipo v1 (producto mínimo viable) |

---

## 2. Qué hace este prototipo

El prototipo v1 implementa un único recorrido vertical: crea un caso judicial, firma cada evento en una cadena de auditoría con hash SHA-256 encadenado y cierra el caso sellando un hash de reporte final, con persistencia en PostgreSQL. Ese recorrido prueba la decisión arquitectónica central del proyecto: la auditoría inalterable (*tamper-evident*) atraviesa las capas de interfaz, lógica y persistencia sin depender de un servicio externo.

Sharur es una aplicación de línea de comandos, sin servicio web ni interfaz gráfica. Su arquitectura prevé la ejecución paralela del script principal y del motor de inteligencia artificial local en terminales independientes; en el v1 solo está activo el núcleo de gestión y auditoría. Los módulos de análisis de red, consola y análisis asistido están presentes como puntos de integración marcados en el código y se activan en las iteraciones siguientes.

Requisitos del catálogo que implementa: **RF-01** (crear caso), **RF-08** (auditoría encadenada), **RF-12** (cierre con hash final), **RNF-01** (tamper-evidence) y **RNF-02** (operación local por línea de comandos).

---

## 3. Requisitos previos

| Componente | Versión |
|---|---|
| Sistema operativo | Linux (Debian, Ubuntu, Kali), WSL2 o Windows 11 |
| Python | 3.12 o superior (probado con 3.12 y 3.13) |
| PostgreSQL | 14 o superior, en ejecución |
| Git | 2.x |

Las dependencias de Python se instalan desde `requirements.txt`: SQLAlchemy 2.0.30 o superior, Pydantic 2.7.0 o superior, pydantic-settings 2.2.1 o superior, python-dotenv 1.0.1 o superior y psycopg2-binary 2.9.9 o superior.

El modelo de inteligencia artificial local no es necesario para el v1. Cuando se habilite, requerirá entre 4 GB (variante liviana) y 8,4 GB (variante completa) de RAM libre.

---

## 4. Instalación

Ejecutar los pasos en este orden.

### 4.1 Preparar la base de datos

Abrir la consola de PostgreSQL (`psql -U postgres`) o el Query Tool de pgAdmin y ejecutar:

```sql
CREATE DATABASE sharur_db;
CREATE USER sharur_user WITH PASSWORD 'sharur_pass';
GRANT ALL PRIVILEGES ON DATABASE sharur_db TO sharur_user;
-- En PostgreSQL 15 o superior, o si aparece un error de permisos al arrancar:
GRANT ALL ON SCHEMA public TO sharur_user;
ALTER DATABASE sharur_db OWNER TO sharur_user;
```

### 4.2 Clonar el repositorio y posicionarse en la etiqueta

```bash
git clone https://github.com/totokugelmann/sharur.git
cd sharur
git checkout v1
```

### 4.3 Instalar las dependencias

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

Editar la variable de conexión para que apunte a la base creada en el paso 4.1:

```
DATABASE_URL=postgresql://sharur_user:sharur_pass@localhost:5432/sharur_db
```

Significado de las variables que usa el v1:

| Variable | Significado |
|---|---|
| `APP_ENV` | Entorno de ejecución (`development`). |
| `DATABASE_URL` | Cadena de conexión a PostgreSQL: usuario, contraseña, servidor, puerto y base. |
| `LOG_LEVEL` | Nivel de detalle del registro de la aplicación (`INFO`). |
| `LOG_DIR`, `REPORTS_DIR`, `EVIDENCE_STORAGE_DIR` | Carpetas locales para registros, reportes y evidencia. |

Las variables `OLLAMA_*` y `NVD_*` corresponden al motor de inteligencia artificial local y a la base nacional de vulnerabilidades, que se activan en iteraciones posteriores; en el v1 pueden dejarse con sus valores de ejemplo. El archivo `.env` real no se versiona.

---

## 6. Ejecución y verificación

### 6.1 Arranque

```bash
python sharur_cli.py
```

Sharur no expone ningún puerto ni dirección web: se opera desde la terminal. En el primer arranque crea automáticamente las tablas sobre la base vacía (casos, eventos de auditoría, órdenes, dispositivos y demás), sin pasos manuales de migración.

### 6.2 Recorrido vertical paso a paso

1. En el menú principal, elegir **`[1] Crear caso`**.
2. Ingresar el **número de expediente**, el **número de oficio** y el **operador**. Resultado esperado: `[+] Caso creado — expediente <número>`.
3. En el menú del caso, elegir **`[4] Ver auditoría del caso`**. Resultado esperado: el evento de creación del caso, con su secuencia y su hash SHA-256.
4. Elegir **`[5] Salir (cierra el caso)`**. Resultado esperado: el caso pasa a estado cerrado y se sella el hash de reporte final.

### 6.3 Verificación de la persistencia

Cerrar la aplicación y consultar la base:

```sql
SELECT numero_causa, estado, hash_reporte_final FROM casos;
SELECT secuencia, hash_evento_anterior, hash_evento FROM eventos_auditoria ORDER BY secuencia;
```

Resultado esperado: el caso figura cerrado con su hash de reporte final, y cada evento conserva el hash del evento anterior, comenzando por un primer evento sin hash previo. Al volver a ejecutar `python sharur_cli.py`, los datos siguen presentes.

### 6.4 Pruebas automatizadas

Con el entorno virtual activado (paso 4.3):

```bash
pip install pytest
pytest tests/ -v
```

Resultado esperado: `5 passed`. En distribuciones que protegen el Python del sistema, como Kali o Debian recientes, `pip` solo funciona dentro del entorno virtual activado.

Las pruebas verifican el criterio de aceptación de RF-08 y RNF-01: que el hash sea determinista, que dependa del evento anterior, y que la alteración de un evento pasado invalide la cadena a partir de ese punto. No requieren base de datos.

---

## 7. Estado del canal de construcción

El canal de integración continua se define en `.github/workflows/ci.yml` y se ejecuta con GitHub Actions en cada envío a la rama principal y en cada etiqueta. En una máquina limpia instala Python 3.12 y las dependencias, y ejecuta las pruebas del núcleo auditable.

El registro de corridas, con su resultado y fecha, se consulta en la pestaña **Actions** del repositorio:
https://github.com/totokugelmann/sharur/actions

---

## 8. Declaración de herramientas auxiliares

Conforme al Protocolo de Uso Autorizado de la cátedra:

| Herramienta | Función | Artefacto afectado |
|---|---|---|
| Asistente de inteligencia artificial | Asistencia de programación y redacción de pruebas automatizadas | Código fuente del prototipo y `tests/` |
| Asistente de inteligencia artificial | Asistencia en la redacción de este archivo de lectura y de la configuración del canal de integración continua | `README.md`, `.github/workflows/ci.yml` |

Ninguna herramienta auxiliar se empleó sobre datos de causas judiciales reales: todas las pruebas se ejecutan sobre datos sintéticos.
