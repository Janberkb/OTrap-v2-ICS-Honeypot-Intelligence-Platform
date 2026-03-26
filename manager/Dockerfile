FROM python:3.12-slim

WORKDIR /app

# System deps for cryptography, asyncpg, and pg_dump/psql
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev libssl-dev curl postgresql-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./manager

# Non-root user
RUN useradd -r -u 1001 -g root otrap \
    && mkdir -p /app/backups /app/logs \
    && chown -R otrap:root /app
USER otrap

EXPOSE 8080 9443

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8080/api/v1/health || exit 1

CMD ["uvicorn", "manager.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--workers", "1", \
     "--log-level", "info"]
