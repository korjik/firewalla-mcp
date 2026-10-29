# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.lock pyproject.toml ./
COPY src ./src
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export PIP_CERT=/run/secrets/proxy_ca; fi; \
    pip install --no-cache-dir -r requirements.lock && pip install --no-cache-dir --no-deps .
USER 10001:10001
ENV FIREWALLA_MCP_CONFIG=/config/config.json PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["firewalla-mcp"]
