# Checklist de Deploy / Atualização

## Primeira instalação

- [ ] Servidor Linux com Docker 24+ e Docker Compose
- [ ] Git, curl, rsync instalados
- [ ] Clonar repositório: `git clone https://github.com/katoonnoass/netops-assistant.git`
- [ ] Copiar `.env`: `cp .env.example .env`
- [ ] Gerar `DJANGO_SECRET_KEY` forte: `python3 -c "import secrets; print(secrets.token_urlsafe(50))"`
- [ ] Ajustar `DJANGO_ALLOWED_HOSTS` e `CSRF_TRUSTED_ORIGINS`
- [ ] Ajustar senha do PostgreSQL em `.env`
- [ ] Build: `docker compose build`
- [ ] Subir: `docker compose up -d`
- [ ] Verificar logs: `docker compose logs -f web`
- [ ] Criar superusuário: `docker compose exec web python manage.py createsuperuser`
- [ ] Setup papéis: `docker compose exec web python manage.py setup_roles`
- [ ] Testar login em http://localhost/
- [ ] Testar envio de snapshot de exemplo

## Atualização

- [ ] Backup antes de atualizar: `bash scripts/docker_backup.sh`
- [ ] `git pull` (se clonado)
- [ ] `docker compose build`
- [ ] `docker compose down --timeout 30`
- [ ] `docker compose up -d`
- [ ] `docker compose exec web python manage.py migrate --noinput`
- [ ] `docker compose exec web python manage.py collectstatic --noinput --clear`
- [ ] `docker compose exec web python manage.py check --deploy`
- [ ] Verificar health: `curl http://localhost/health/`
- [ ] Verificar logs: `docker compose logs --tail=50 web`
- [ ] Testar login e funcionalidades básicas

## Rollback manual

- [ ] Restaurar dump PostgreSQL: `gunzip -c backups/postgres_*.sql.gz | docker compose exec -T db psql -U netops netops_assistant`
- [ ] Restaurar backup operacional (se necessário): *implementar manualmente via Django*
- [ ] Reverter código: `git checkout <tag-anterior>`
- [ ] Rebuild e redeploy

## Verificações pós-deploy

- [ ] Health check: `curl http://localhost/health/` → `ok`
- [ ] Dashboard acessível sem erro 500
- [ ] Upload de config de exemplo funciona
- [ ] Busca global retorna resultados
- [ ] Backup funciona: `bash scripts/docker_backup.sh`
- [ ] Logs sem erros críticos
