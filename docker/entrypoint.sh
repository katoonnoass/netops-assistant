#!/bin/bash
# Entrypoint para container web do NetOps Assistant
set -e

echo "==> Aguardando PostgreSQL ficar disponivel..."
until PGPASSWORD="$POSTGRES_PASSWORD" psql -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c '\q' 2>/dev/null; do
  echo "PostgreSQL indisponivel — aguardando..."
  sleep 2
done
echo "PostgreSQL disponivel!"

echo "==> Rodando migrate..."
python manage.py migrate --noinput

echo "==> Coletando static files..."
python manage.py collectstatic --noinput --clear

echo "==> Aplicando setup_roles (idempotente)..."
python manage.py setup_roles 2>/dev/null || echo "Comando setup_roles nao encontrado ou ja executado."

echo "==> Iniciando Gunicorn..."
exec "$@"
