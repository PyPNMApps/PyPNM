### Summary
Added a runtime-data cleanup line in the Dockerfile to keep `.data/` out of container layers for M0 release hygiene. This bundle includes the Dockerfile content only.

### Modified Files
- /home/dev01/Projects/PyPNM/Dockerfile

### Commands Executed And Results
- None recorded in this bundle.

### Tests
- pytest → not run (not recorded in this bundle).
- ruff → not run (not recorded in this bundle).

### Notes / Warnings
- None.

### Remaining TODOs / Follow-Ups
- None.

# FILE: /home/dev01/Projects/PyPNM/Dockerfile
# syntax=docker/dockerfile:1.6

ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates gosu iputils-ping \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE /app/
COPY src/ /app/src/
COPY demo/ /app/demo/
COPY deploy/docker/config/ /app/deploy/config/
COPY tools/ /app/tools/
COPY docker/entrypoint.sh /app/entrypoint.sh

RUN python -m pip install --upgrade pip \
 && python -m pip install . \
 && useradd -m -u 10001 -s /usr/sbin/nologin pypnm \
 && chmod +x /app/entrypoint.sh \
 && if [ -f /app/deploy/config/system.json.template ] && [ ! -f /app/deploy/config/system.json ]; then cp /app/deploy/config/system.json.template /app/deploy/config/system.json; fi \
 && rm -rf /app/.data

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "-m", "uvicorn", "pypnm.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
