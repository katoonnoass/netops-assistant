#!/bin/bash
# scripts/docker_backup.sh
# Backup operacional + pg_dump com retenção
# Uso: bash scripts/docker_backup.sh [--include-raw-config]
#      BACKUP_RETENTION_DAYS=14 bash scripts/docker_backup.sh
set -e

BACKUP_DIR="${BACKUP_DIR:-backups}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
INCLUDE_RAW=""

if [ "$1" == "--include-raw-config" ]; then
  INCLUDE_RAW="--include-raw-config"
fi

mkdir -p "$BACKUP_DIR"

echo "==> [$(date)] Iniciando backup..."

# Backup operacional sem raw config (sempre)
echo "--> Exportando backup operacional..."
docker compose exec -T web python manage.py export_operational_backup \
  --output "/app/backups/netops_operational_${TIMESTAMP}.json"
gzip -f "${BACKUP_DIR}/netops_operational_${TIMESTAMP}.json" 2>/dev/null || true
echo "OK: ${BACKUP_DIR}/netops_operational_${TIMESTAMP}.json.gz"

# Backup operacional com raw config (opcional)
if [ "$INCLUDE_RAW" != "" ]; then
  echo "--> Exportando backup operacional (com raw config)..."
  docker compose exec -T web python manage.py export_operational_backup \
    --output "/app/backups/netops_operational_raw_${TIMESTAMP}.json" --include-raw-config
  gzip -f "${BACKUP_DIR}/netops_operational_raw_${TIMESTAMP}.json" 2>/dev/null || true
  echo "OK: ${BACKUP_DIR}/netops_operational_raw_${TIMESTAMP}.json.gz"
fi

# Dump PostgreSQL
echo "--> Exportando dump PostgreSQL..."
docker compose exec -T db pg_dump -U netops netops_assistant > "${BACKUP_DIR}/postgres_${TIMESTAMP}.sql"
gzip -f "${BACKUP_DIR}/postgres_${TIMESTAMP}.sql"
echo "OK: ${BACKUP_DIR}/postgres_${TIMESTAMP}.sql.gz"

# Limpeza de backups antigos
echo "--> Removendo backups com mais de ${RETENTION_DAYS} dias..."
find "$BACKUP_DIR" -name "netops_operational_*.json.gz" -mtime +${RETENTION_DAYS} -delete 2>/dev/null || true
find "$BACKUP_DIR" -name "netops_operational_raw_*.json.gz" -mtime +${RETENTION_DAYS} -delete 2>/dev/null || true
find "$BACKUP_DIR" -name "postgres_*.sql.gz" -mtime +${RETENTION_DAYS} -delete 2>/dev/null || true

echo "==> [$(date)] Backup concluido em ${BACKUP_DIR}/"
echo "    Retencao: ${RETENTION_DAYS} dias"
ls -lh "${BACKUP_DIR}/" | tail -n +2
