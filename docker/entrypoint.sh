#!/bin/bash
# Entrypoint para container web do NetOps Assistant
set -e

echo "==> Aguardando PostgreSQL ficar disponivel..."
python -c "
import os, time, psycopg2 as p
while True:
    try:
        p.connect(
            dbname=os.environ['POSTGRES_DB'],
            user=os.environ['POSTGRES_USER'],
            password=os.environ['POSTGRES_PASSWORD'],
            host=os.environ['POSTGRES_HOST'],
            port=os.environ.get('POSTGRES_PORT', '5432'),
            connect_timeout=2
        ).close()
        break
    except Exception:
        time.sleep(2)
"
echo "PostgreSQL disponivel!"

echo "==> Rodando migrate..."
python manage.py migrate --noinput

echo "==> Coletando static files..."
python manage.py collectstatic --noinput --clear

echo "==> Aplicando setup_roles (idempotente)..."
python manage.py setup_roles 2>/dev/null || echo "Comando setup_roles nao encontrado ou ja executado."

echo "==> Iniciando Gunicorn..."
exec "$@"
