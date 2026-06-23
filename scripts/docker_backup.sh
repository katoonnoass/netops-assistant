#!/bin/bash
# backup_docker.sh — Exporta backup operacional e dump PostgreSQL
# Uso: ./scripts/docker_backup.sh [--raw]
set -e

BACKUP_DIR="backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p "$BACKUP_DIR"

echo "==> Exportando backup operacional Django..."
if [ "$1" == "--raw" ]; then
  docker compose exec -T web python manage.py export_operational_backup \
    --output "/app/backups/netops_backup_${TIMESTAMP}_with_raw.json" --include-raw-config
  echo "Backup com raw config: backups/netops_backup_${TIMESTAMP}_with_raw.json"
else
  docker compose exec -T web python manage.py export_operational_backup \
    --output "/app/backups/netops_backup_${TIMESTAMP}.json"
  echo "Backup: backups/netops_backup_${TIMESTAMP}.json"
fi

echo "==> Exportando dump PostgreSQL..."
docker compose exec -T db pg_dump -U netops netops_assistant > "${BACKUP_DIR}/postgres_dump_${TIMESTAMP}.sql"
echo "Dump: backups/postgres_dump_${TIMESTAMP}.sql"

echo "==> Backup concluido em ${TIMESTAMP}"
