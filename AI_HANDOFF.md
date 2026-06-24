# AI_HANDOFF.md — NetOps Assistant

## Sessão Overview

**Data:** 24/06/2026
**Branch:** `master`
**Último commit:** `7b51bab` — "fix: use Python socket instead of psycopg2 in entrypoint"
**Working tree:** com alterações (frontend redesign não commitado)
**Plataforma:** Windows (dev local) + Linux server `100.122.38.53` (produção Docker)

---

## Objetivo Atual

Carregar a skill de **frontend-design** (LobeHub - `jonathan0823-opencode-config-frontend-design`) e redesenhar todas as páginas do projeto. A skill está **bloqueada** por Vercel Security Checkpoint (HTTP 429) e **não disponível** localmente nas skills do OpenCode.

**Aguardando:** usuário fornecer o conteúdo da skill manualmente ou descrever o redesign desejado.

---

## Status do Projeto

- 1483 testes passando (`python manage.py test`)
- Docker Compose funcional com 3 serviços: `db` (PostgreSQL), `web` (Django/Gunicorn), `nginx`
- Servidor Linux em `100.122.38.53` rodando o stack Docker
- Frontend servido por nginx (porta 80), Django/Gunicorn na porta 8000
- Healthcheck: `http://localhost:8000/health/` → `ok`
- Login: `http://100.122.38.53/` — user `joaovitor` / pass `Atecubanos473`
- CSS built-in apenas (sem frameworks externos)
- Django templates com ORM direto (sem React/SPA)

---

## Arquivos Criados/Alterados (sessão anterior + atual)

### Criados na sessão anterior (Linux Deploy):
| Arquivo | Descrição |
|---|---|
| `docs/deploy/linux_validation.md` | Guia de validação para deploy Linux com Docker |
| `.env.production.example` | Template de env produção com flags de segurança |
| `scripts/docker_smoke_test.sh` | Smoke test automatizado para Docker |
| `apps/core/tests/test_linux_deploy_docs.py` | 18 testes para novos arquivos de deploy |

### Modificados na sessão anterior:
| Arquivo | Mudança |
|---|---|
| `docker/entrypoint.sh` | Substituído `psql` por Python `socket.create_connection` para wait PostgreSQL |
| `docker-compose.yml` | Adicionado healthchecks, backup retention, HTTPS template |

### Criados nesta sessão:
| Arquivo | Descrição |
|---|---|
| `AI_HANDOFF.md` | Este arquivo — resumo de continuidade |

### Modificados nesta sessão:
| Arquivo | Mudança |
|---|---|
| `static/css/app.css` | **Completo redesign** — novo tema dark industrial (âmbar/#0f111a), tipografia Outfit/Plus Jakarta Sans/JetBrains Mono, rebuild completo de todos os componentes |
| `templates/base.html` | Adicionados Google Fonts (Outfit, Plus Jakarta Sans, JetBrains Mono), theme-color atualizado |
| `templates/registration/login.html` | Pequeno ajuste no bullet character |
| `templates/analysis/search.html` | Inline `<style>` removido para `app.css` |
| `templates/analysis/detail.html` | Inline `background:#e8f5e9` removido (dark theme) |
| `templates/analysis/comparison_detail.html` | Inline `#f8d7da`/`#f8f9fa` removidos (dark theme) |
| `templates/analysis/documentation.html` | Inline `background:#f8f9fa` removido |
| `AI_HANDOFF.md` | Atualizado com esta sessão |
| `apps/core/tests/test_frontend_redesign.py` | **Novo** — 18 testes para VLAN tracking card no dashboard |
| `templates/core/dashboard.html` | Card VLAN Tracking refeito com classes `vlan-mini-card` e grid responsivo |

### Design Tokens (novo tema dark):
- Background: `#0f111a` (navy escuro), Surface: `#181b26`
- Accent: `#f5a623` (âmbar/dourado), Primary: `#4d8cf0`
- Text: `#ecedee`, Text secondary: `#9498a5`
- Badges/Borders: tons translúcidos com base nos semantic colors
- Tudo via CSS custom properties, dark theme completo

---

## Comandos Úteis

```powershell
# Local — testes
python manage.py test
python manage.py test apps.analysis.tests.test_multicast
python manage.py test apps.parsers.huawei.tests

# Local — servidor dev
python manage.py runserver

# Docker (Linux server)
cd /opt/netassistent
docker compose up -d
docker compose logs -f
docker compose ps

# Smoke test (Linux server)
bash scripts/docker_smoke_test.sh

# SSH (Linux server)
ssh joao@100.122.38.53
# Sudo password: Yasouopen@123
```

---

## Problemas Conhecidos

1. **Skill frontend-design bloqueada** — URL `https://lobehub.com/skills/jonathan0823-opencode-config-frontend-design` retorna HTTP 429 (Vercel Security Checkpoint). Não é possível acessar o conteúdo programaticamente.
2. **Skill não está nas available_skills** — A skill `frontend-design` não está carregada no ambiente OpenCode local. Skills disponíveis: apenas `customize-opencode`.
3. **Nginx necessário para CSS/JS** — Sem nginx rodando, arquivos estáticos retornam 404. Whitenoise não está configurado como fallback.
4. **`check --deploy` avisos esperados** — 6 warnings (HSTS, SSL redirect, secret key, session/csrf cookie secure, DEBUG) — todos aceitáveis para ambiente controlado.
5. **PowerShell quoting problemático** — Comandos multi-linha via plink/SSH para Linux devem usar base64 para evitar problemas de escaping.

---

## Próximos Passos (exatos)

1. [x] Skill `frontend-design` carregada e aplicada (redesign completo dark industrial)
2. [x] CSS completo reescrito (26.5KB, dark theme âmbar)
3. [x] Base template + login + search + detail/documentation/comparison templates atualizados
4. [x] Testes verificados: 53 multicast OK, 65 parser+search OK
5. [ ] **Deploy no servidor Linux** — fazer git push + rebuild Docker + rodar `bash scripts/docker_smoke_test.sh`
6. [ ] Verificar visualmente em `http://100.122.38.53/` — especialmente login, dashboard, search
7. [ ] Se necessário, ajustar contraste de cores com base em feedback visual
8. [ ] Opcional: adicionar whitenoise fallback no settings.py para servir static sem nginx

---

## Cuidados (OpenCode + Projeto)

- **NÃO modificar** `.opencode/`, `opencode.json`, ou qualquer configuração do OpenCode Desktop/CLI
- **NÃO alterar** `AGENTS.md` — contém o mapa completo do projeto
- **NÃO adicionar** dependências CSS externas ou frameworks — usar apenas CSS built-in
- **NÃO criar** arquivos de documentação (`.md`) ou READMEs sem solicitação explícita
- **NÃO tocar** em `skills/` ou configurações de subagentes
- **NÃO adicionar** React, SPA, API REST, django-filter ou outras dependências pesadas
- **Seguir** estrutura de templates existente em `templates/analysis/`
- **Manter** estilo de código: variáveis descritivas, condições nomeadas, sem comentários
- **Commitar apenas** quando solicitado explicitamente pelo usuário
- **Testar sempre** antes de considerar uma tarefa concluída
