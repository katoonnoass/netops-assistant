# Guia de Homologação — Collector / Coleta Automática

Guia para validar o funcionamento do Collector em ambiente de laboratório antes de usar em produção.

---

## Pré-requisitos

- Servidor Linux ou Windows com Python 3.12+ e dependências instaladas
- Acesso SNMP aos equipamentos de laboratório
- Acesso SSH com usuário **read-only** ou **backup**
- Portas SNMP (161/UDP) e SSH (22/TCP) liberadas no firewall
- `.env` configurado com `COLLECTOR_SECRET_KEY`

---

## 1. Criar credencial

Pelo admin Django (`/admin/collector/networkcredential/`):

```
Nome: LAB-CRED
Usuário SSH: backup
Senha SSH: <senha-do-laboratorio>
Comunidade SNMP: public
Versão SNMP: v2c
Prioridade: 10
Ativo: Sim
```

> A senha SSH será criptografada com Fernet antes de armazenar.
> A comunidade SNMP **não** é criptografada — use apenas em laboratório.

---

## 2. Criar perfil

Pelo admin Django (`/admin/collector/discoveryprofile/`):

```
Nome: LAB-OLT
Descrição: Perfil de homologação para OLTs
Sub-redes: ["10.100.0.0/24", "10.100.1.0/24"]
Credencial: LAB-CRED
Timeout: 10
Threads: 3
Ativo: Sim
```

---

## 3. Testar descoberta com `--dry-run`

```bash
python manage.py discover_network --profile "LAB-OLT" --dry-run
```

Saída esperada:

```
=== MODO DRY-RUN ===
Descobrindo dispositivos via SNMP em LAB-OLT...
[DRY-RUN] Descobriria: 10.100.0.1 (OLT-HW-MATRIZ-01)
[DRY-RUN] Descobriria: 10.100.0.2 (OLT-ZTE-MATRIZ-02)
...
Resumo: 2 dispositivos seriam descobertos.
Nenhum dado foi alterado.
```

---

## 4. Testar SNMP em um único IP

Para testar a descoberta SNMP em apenas um dispositivo, crie um perfil com uma sub-rede `/32`:

```
Sub-redes: ["10.100.0.1/32"]
```

```bash
python manage.py discover_network --profile "LAB-SINGLE" --dry-run
python manage.py discover_network --profile "LAB-SINGLE"
```

Verifique no admin que o dispositivo foi criado com `collector_enabled=True` e `last_discovered_at` preenchido.

---

## 5. Testar SSH em um único dispositivo

Após a descoberta, teste a coleta SSH:

```bash
python manage.py collect_device_configs --device "OLT-HW-MATRIZ-01" --dry-run
python manage.py collect_device_configs --device "OLT-HW-MATRIZ-01" --analyze
```

Verifique:
- Um `ConfigSnapshot(source="auto")` foi criado
- O snapshot foi analisado (circuitos, serviços, issues)
- `device.last_collected_at` foi atualizado
- O snapshot aparece em `/devices/<pk>/snapshots/`

---

## 6. Execução completa

```bash
python manage.py run_collector --profile "LAB-OLT" --discover --collect --analyze
```

---

## 7. Verificar na Web

- `/collector/` — Dashboard do Collector
  - Total de execuções, perfis ativos, devices com coleta habilitada
  - Últimas execuções e status
  - Dispositivos coletados recentemente
  - Últimos erros
- `/collector/runs/` — Lista de execuções com filtros
- `/collector/runs/<pk>/` — Detalhe da execução (tarefas, duração)
- `/collector/tasks/` — Lista de tarefas
- `/collector/tasks/<pk>/` — Detalhe da tarefa (log, erro mascarado)
- `/collector/profiles/` — Perfis de descoberta
- `/collector/devices/` — Status dos dispositivos

### Dashboard principal (`/`)

- Verificar se o card "Coleta automática" aparece
- Verificar se mostra a última execução, total de coletas, falhas
- Verificar se o link "Abrir Collector →" funciona

### Busca global (`/search/`)

- Buscar por `collector` — deve mostrar seção "Collector / Coleta Automática"
- Buscar por `snmp` — deve mostrar tarefas SNMP
- Buscar por `failed` — deve mostrar execuções com falha
- Buscar por nome do profile — deve mostrar o perfil e execuções

### Detalhe do dispositivo (`/devices/<pk>/`)

- Verificar seção "Collector / Coleta Automática"
  - Status da coleta automática (ativado/desativado)
  - Portas SSH e SNMP
  - Última descoberta e última coleta
  - Últimas tarefas
  - Último erro (se houver)
  - Links para status dos dispositivos e última execução

---

## 8. Verificar logs sem secrets

Os logs e erros NUNCA devem exibir:
- Senhas SSH
- Comunidades SNMP
- Enable secrets

Verifique em:
- Página de detalhe da tarefa (`/collector/tasks/<pk>/`)
- Página de detalhe do perfil (`/collector/profiles/<pk>/`)
- Lista de perfis (`/collector/profiles/`)

---

## 9. CLI network_search

```bash
python manage.py network_search "collector"
python manage.py network_search "snmp"
python manage.py network_search "ssh"
python manage.py network_search "LAB-OLT"
python manage.py network_search "failed"
python manage.py network_search "erro"
```

Cada comando deve mostrar a seção `--- Collector ---` com resultados.

---

## 10. Rollback

Para desabilitar a coleta em um dispositivo:

```bash
python manage.py shell -c "from apps.devices.models import Device; Device.objects.filter(name='OLT-HW-MATRIZ-01').update(collector_enabled=False)"
```

Ou pelo admin: `/admin/devices/device/<pk>/change/` → desmarcar "Coleta automática".

---

## Checklist de Segurança

- [ ] Usuário SSH é **read-only** ou **backup**, não root
- [ ] Comunidade SNMP é **read-only** (ro), não rw
- [ ] Senhas SSH são criptografadas (Fernet) no banco
- [ ] `COLLECTOR_SECRET_KEY` está no `.env` e **não** no código
- [ ] Dispositivos de produção têm `collector_enabled=True` apenas se necessário
- [ ] Perfis de descoberta apontam para sub-redes corretas (sem vazar para redes externas)
- [ ] Logs e erros não contêm secrets (verificado visualmente)
- [ ] Acesso web ao Collector exige login (padrão: qualquer usuário autenticado)
- [ ] Snapshots com `source="auto"` têm o mesmo tratamento de segurança que upload manual
