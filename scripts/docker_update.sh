#!/bin/bash
# scripts/docker_update.sh
# Atualizacao segura do NetOps Assistant via Docker
# Uso: bash scripts/docker_update.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

echo "==> [$(date)] Iniciando atualizacao do NetOps Assistant..."

# Verificar se e um repositorio git
if [ -d ".git" ]; then
  echo "--> Atualizando codigo via git pull..."
  git pull
else
  echo "AVISO: Diretorio nao e um repositorio git. Pule git pull manualmente."
fi

echo "--> Rebuild das imagens..."
docker compose build

echo "--> Parando containers existentes..."
docker compose down --timeout 30

echo "--> Subindo containers..."
docker compose up -d

echo "--> Aguardando web ficar saudavel..."
sleep 10

echo "--> Rodando migrations..."
docker compose exec web python manage.py migrate --noinput

echo "--> Coletando static files..."
docker compose exec web python manage.py collectstatic --noinput --clear

echo "--> Verificando sistema..."
docker compose exec web python manage.py check --deploy

echo "--> Status dos containers..."
docker compose ps

echo ""
echo "==> [$(date)] Atualizacao concluida!"
echo "    Acesse: http://localhost/"
echo "    Logs: docker compose logs -f web"
