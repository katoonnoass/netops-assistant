# Linux Validation Guide — NetOps Assistant

Guia de validação para deploy em servidor Linux com Docker.

## Pré-requisitos

- Linux server (Ubuntu 22.04+ ou Debian 12+ recomendado)
- Docker 24+ e Docker Compose plugin
- Git
- Porta 80 liberada no firewall
- Espaço em disco suficiente para imagens, volumes e backups
- Usuário com permissão para executar Docker (membro do grupo `docker`)

## Clone

```bash
git clone https://github.com/katoonnoass/netops-assistant.git
cd netops-assistant
```

## Configuração `.env`

```bash
cp .env.example .env
nano .env
```

Campos obrigatórios:

| Variável | Descrição |
|----------|-----------|
| `DJANGO_SECRET_KEY` | Gere com `python3 -c "import secrets; print(secrets.token_urlsafe(50))"` |
| `DJANGO_DEBUG` | `False` em produção |
| `DJANGO_ALLOWED_HOSTS` | Domínio e/ou IP do servidor |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | Origens confiáveis para CSRF |
| `POSTGRES_PASSWORD` | Altere para uma senha forte |

Para produção com HTTPS, veja também `.env.production.example`.

## Validação do Compose

```bash
docker compose config
docker compose build
docker compose up -d
docker compose ps
docker compose logs -f web
docker compose logs -f nginx
```

## Health Check

```bash
curl -I http://localhost/health/
curl http://localhost/health/
```

Esperado:

```
HTTP/1.1 200 OK
ok
```

## Criar administrador

```bash
docker compose exec web python manage.py createsuperuser
docker compose exec web python manage.py setup_roles
```

## Smoke Test — Navegador

- `/accounts/login/` — página de login
- `/` — dashboard
- `/devices/` — lista de dispositivos
- `/search/` — busca global
- `/vlan/` — VLAN Tracking
- `/admin-tools/backup/` — ferramentas de backup

## Testes dentro do container

```bash
docker compose exec web python manage.py check
docker compose exec web python manage.py check --deploy
docker compose exec web python manage.py test
```

O `check --deploy` pode alertar sobre HTTPS/HSTS/cookies secure caso não estejam ativados no `.env`. Isso é esperado se o proxy HTTPS final ainda não estiver configurado.

## Smoke Test Automatizado

```bash
bash scripts/docker_smoke_test.sh
```

## Próximos passos

- Configurar HTTPS (veja `docker/nginx/https.example.conf`)
- Ajustar `DJANGO_SECURE_SSL_REDIRECT`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`
- Configurar backup via cron (veja `docs/deploy/backup_cron.md`)
- Revisar checklist de produção (veja `docs/deploy/checklist.md`)
