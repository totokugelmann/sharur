# Sharur SAIC - docker/Dockerfile
#
# Imagen de la API FastAPI. Las herramientas de reconocimiento
# (nmap, whois, dig, httpx, nuclei, testssl.sh) se instalan aca
# porque tools_service.py y consola_service.py las invocan via
# subprocess. No se instala NINGUNA herramienta de explotacion.

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/sharur

# Dependencias de sistema + herramientas de reconocimiento autorizadas
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        dnsutils \
        whois \
        nmap \
        iptables \
        sudo \
        ca-certificates \
        gnupg \
    && rm -rf /var/lib/apt/lists/*

# httpx / nuclei / katana (proyectool ProjectDiscovery) via Go binaries precompilados
# se recomienda fijar versiones especificas en produccion.
RUN curl -sSfL https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_amd64.zip -o /tmp/httpx.zip \
    && unzip -q /tmp/httpx.zip -d /usr/local/bin httpx || true \
    && rm -f /tmp/httpx.zip

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini .

RUN useradd --create-home --shell /bin/bash sharur \
    && mkdir -p /srv/sharur/logs /srv/sharur/evidence_storage /srv/sharur/reports \
    && chown -R sharur:sharur /srv/sharur

USER sharur

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
