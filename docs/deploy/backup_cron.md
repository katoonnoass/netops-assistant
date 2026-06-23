# Backup Automático — Cron

## Crontab (exemplo para usuário root ou deploy)

```cron
# Diario — 02:00 — backup operacional sem raw config
0 2 * * * cd /opt/netops-assistant && bash scripts/docker_backup.sh >> backups/backup_daily.log 2>&1

# Semanal — domingo 03:00 — backup completo com raw config
0 3 * * 0 cd /opt/netops-assistant && bash scripts/docker_backup.sh --include-raw-config >> backups/backup_weekly.log 2>&1
```

## Como instalar

```bash
crontab -e
# Cole as linhas acima
# Salve e saia
# Verifique:
crontab -l
```

## Logs

Os logs de cada execução ficam em:

```text
backups/backup_daily.log
backups/backup_weekly.log
```

Verifique periodicamente:

```bash
tail -f backups/backup_daily.log
```

## Retenção

O padrão é manter backups dos últimos **7 dias** (configurável via `BACKUP_RETENTION_DAYS`).

```bash
BACKUP_RETENTION_DAYS=14 bash scripts/docker_backup.sh
```

## Arquivos gerados

```text
backups/
├── netops_operational_YYYYMMDD_HHMMSS.json.gz
├── netops_operational_raw_YYYYMMDD_HHMMSS.json.gz   (apenas --include-raw-config)
├── postgres_YYYYMMDD_HHMMSS.sql.gz
└── backup_daily.log
```

## Copiar backup para outro servidor

```bash
rsync -avz backups/ user@servidor-backup:/caminho/backups/
```

## ⚠ Atenção

- Backups com `--include-raw-config` contêm configurações brutas dos equipamentos, incluindo senhas em texto claro (se presentes na config original).
- Mantenha esses backups em local seguro e com acesso restrito.
- Nunca exponha raw config em redes públicas.
