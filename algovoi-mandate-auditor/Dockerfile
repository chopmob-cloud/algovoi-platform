# AlgoVoi Mandate Auditor Service
# Self-contained audit + verification service for payment mandate charge chains.
#
# GET  /v1/audit/{kid}/{mandate_id}          -- live audit report (JSON)
# GET  /v1/audit/{kid}/{mandate_id}/export   -- downloadable audit pack (attachment)
# GET  /health                               -- liveness probe
#
# Reads from the same mandates.db as the mandate service.
# docker build -t algovoi-mandate-auditor:0.1.0 -f Dockerfile .

FROM python:3.11-slim

LABEL org.opencontainers.image.title="AlgoVoi Mandate Auditor"
LABEL org.opencontainers.image.description="Mandate Auditor Suite -- retention-chain audit reports for payment mandate charge histories."
LABEL org.opencontainers.image.vendor="AlgoVoi"
LABEL org.opencontainers.image.licenses="LicenseRef-AlgoVoi-Commercial"
LABEL org.opencontainers.image.version="0.1.0"

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY algovoi_mandate_auditor ./algovoi_mandate_auditor
COPY scripts ./scripts

# Retention chain and mandate are installed from the private index in production.
# In local/CI builds, bind-mount or COPY them first, then install.
RUN pip install --no-cache-dir fastapi uvicorn pydantic

RUN adduser --disabled-password --gecos "" appuser && chown -R appuser /app
USER appuser

ENV PYTHONUNBUFFERED=1
ENV MANDATE_AUDITOR_BIND=0.0.0.0:8097
ENV MANDATE_STORE_PATH=/data/mandates.db

EXPOSE 8097

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -sf http://localhost:8097/health || exit 1

CMD ["sh", "-c", "uvicorn algovoi_mandate_auditor.service:app --host $(echo $MANDATE_AUDITOR_BIND | cut -d: -f1) --port $(echo $MANDATE_AUDITOR_BIND | cut -d: -f2) --log-level info"]
