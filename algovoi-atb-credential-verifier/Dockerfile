# ATB Credential Verifier Service — verify ATB Phase-2 agent-trust credentials.
#
# GET  /health   liveness + issuer count
# POST /verify   verify an X-ATB-Credential / X-ATB-ZK-Credential header value
#
# Bridges into the substrate-2 control plane: set S2_HUB_URL (+ S2_HUB_TOKEN) and it
# pulls its trust set and self-registers. Build context: algovoi-atb-credential-verifier/
FROM python:3.11-slim

LABEL org.opencontainers.image.title="AlgoVoi ATB Credential Verifier"
LABEL org.opencontainers.image.description="Verify ATB Phase-2 (Falcon-1024 + Bulletproofs) agent-trust credentials offline."
LABEL org.opencontainers.image.vendor="AlgoVoi"
LABEL org.opencontainers.image.version="0.1.0"

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY app ./app
COPY scripts ./scripts
COPY wheels/ ./wheels/

# Install with serve + verify extras. --find-links vendors the private bpverify wheel
# (real Bulletproofs verification); pqcrypto + rfc8785 resolve from PyPI.
RUN pip install --no-cache-dir --find-links=./wheels -e ".[serve,verify]"

RUN adduser --disabled-password --gecos "" appuser && mkdir -p /app/data && chown -R appuser /app
USER appuser

ENV PYTHONUNBUFFERED=1
ENV ATB_VERIFIER_BIND=0.0.0.0:8095

EXPOSE 8095

HEALTHCHECK --interval=15s --timeout=5s --start-period=8s --retries=3 \
  CMD curl -sf http://localhost:8095/health || exit 1

CMD ["sh", "-c", "uvicorn app.main:app --host $(echo $ATB_VERIFIER_BIND | cut -d: -f1) --port $(echo $ATB_VERIFIER_BIND | cut -d: -f2) --log-level info"]
