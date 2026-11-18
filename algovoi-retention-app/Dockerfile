FROM python:3.11-slim
WORKDIR /app

# Offline-installable: drop the wheel set under /wheels for an air-gapped build,
# else this resolves algovoi-retention-chain + deps from the configured index.
COPY pyproject.toml README.md ./
COPY src ./src

ARG PIP_FIND_LINKS=""
ENV PIP_FIND_LINKS=${PIP_FIND_LINKS}
RUN pip install --no-cache-dir ".[serve]"

ENV RETENTION_APP_BIND=0.0.0.0:8097 \
    RETENTION_DATA_DIR=/data \
    RETENTION_DB=/data/retention.db
EXPOSE 8097
VOLUME ["/data"]
CMD ["algovoi-retention-app-serve"]
