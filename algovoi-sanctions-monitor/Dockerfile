# AlgoVoi Sanctions Monitor appliance — continuous re-screening + signed delta receipts.
# Stateful: the SQLite watchlist lives at /app/data (PQC-encrypted at rest). MOUNT A VOLUME there, e.g.
#   docker run -v monitor_data:/app/data -e MONITOR_MLKEM_PK_B64=... -e MONITOR_MLKEM_SK_B64=... ...
# Not sealed (no key-custody secret); the engine ships as readable Python.
FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY examples ./examples

RUN pip install --no-cache-dir ".[service]" \
    && mkdir -p /app/data \
    && adduser --disabled-password --gecos "" appuser \
    && chown -R appuser /app

USER appuser

# SECURITY (2026-08-20): MONITOR_HOST=0.0.0.0 is for reachability behind a reverse proxy. The entrypoint
# now REFUSES to start on a non-loopback bind without MONITOR_API_TOKEN (the watchlist/deltas/DELETE
# endpoints must not be unauthenticated). Supply MONITOR_API_TOKEN at deploy time (docker run -e / compose),
# or set MONITOR_HOST=127.0.0.1 for a same-host proxy. Never bake the token into the image.
ENV MONITOR_DB=/app/data/monitor.db \
    MONITOR_HOST=0.0.0.0 \
    MONITOR_PORT=8088 \
    PYTHONUNBUFFERED=1

EXPOSE 8088
VOLUME ["/app/data"]

HEALTHCHECK --interval=15s --timeout=5s --retries=5 --start-period=20s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8088/healthz').status==200 else 1)" || exit 1

CMD ["python", "examples/run_service.py"]
