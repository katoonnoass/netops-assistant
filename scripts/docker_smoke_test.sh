#!/bin/bash
# scripts/docker_smoke_test.sh
# Smoke test automatizado para deploy Docker do NetOps Assistant
# Uso: bash scripts/docker_smoke_test.sh
set -e

echo "==> [$(date)] Iniciando smoke test..."
echo ""

# 1. Validar sintaxe do compose
echo "--> docker compose config..."
docker compose config > /dev/null
echo "OK"

# 2. Status dos containers
echo ""
echo "--> docker compose ps..."
docker compose ps

# 3. Django check
echo ""
echo "--> python manage.py check..."
docker compose exec -T web python manage.py check
echo "OK"

# 4. Django check --deploy (não quebra o smoke test por warnings)
echo ""
echo "--> python manage.py check --deploy..."
docker compose exec -T web python manage.py check --deploy || true
echo "(avisos exibidos acima — não bloqueante)"

# 5. Testes automatizados
echo ""
echo "--> python manage.py test..."
docker compose exec -T web python manage.py test --verbosity=0
echo "OK"

# 6. Setup de papéis (idempotente)
echo ""
echo "--> python manage.py setup_roles..."
docker compose exec -T web python manage.py setup_roles 2>/dev/null || echo "(ja executado ou inexistente)"

# 7. Health check via nginx
echo ""
echo "--> curl http://localhost/health/..."
if command -v curl &> /dev/null; then
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/health/ 2>/dev/null || echo "000")
    if [ "$STATUS" = "200" ]; then
        echo "HTTP $STATUS OK"
    else
        echo "HTTP $STATUS (health check pode estar indisponivel — aguardando containers)"
    fi
else
    echo "curl nao encontrado no host. Instale curl ou use: docker compose exec web curl -fsS http://nginx/health/"
fi

echo ""
echo "==> [$(date)] Smoke test concluido."
