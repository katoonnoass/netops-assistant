FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/staticfiles /app/media /app/backups

EXPOSE 8000

RUN useradd --no-create-home -u 1000 netops && chown -R netops:netops /app
USER netops

ENTRYPOINT ["/app/docker/entrypoint.sh"]

CMD ["gunicorn", "netops_assistant.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "120"]
