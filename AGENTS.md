# Memory

## Project Overview
See @README.md for project overview and @package.json for available npm/pnpm commands for this project.

## Code Style Guidelines
- Use descriptive variable names
- Follow existing patterns in the codebase
- Extract complex conditions into meaningful boolean variables
- Use Django templates with direct ORM queries instead of frontend frameworks (React, SPA)
- Implement filters manually with QuerySet instead of using django-filter
- Use only built-in CSS without external frameworks or dependencies
- Never store real secrets, passwords, community strings, or keys in parsed_data — only flags (has_password, password_type, has_secret)
- Create dedicated test files per feature domain (e.g., test_management.py for management/observability tests) instead of adding to monolithic test files

## Architecture Notes

### Search System (`apps/analysis/search.py`)
- `global_network_search()` is the single entry point; returns 12 sections including `multicast` and `policies`
- `_search_multicast()` searches multicast routing, PIM static-RPs/BSR/RP-candidates, PIM/IGMP/MLD interfaces, IGMP snooping global/VLANs, multicast VPN-instances
- `_search_policies()` searches route-policies, ip-prefixes, ACLs, as-path-filters, community-filters, and BGP policy dependencies
- Smart matching strips common prefixes (`acl `, `route-policy `, `ip-prefix `, `as-path-filter `, `community-filter `) for broader results
- Generic type-only queries (`route-policy`, `ip-prefix`, `acl`) match ALL items of that type
- Evidence is extracted from raw config text via `_get_evidence_lines()` with ±2 lines context
- Query classification handles: ip, prefix, vlan, interface, asn, text types
- CLI `python manage.py network_search "<query>"` now displays policies and multicast sections

### Policy Data Structures (`apps/parsers/huawei/parser.py`)
All stored in `parsed_data` dict:
- `route_policies`: list of dicts with name, node, action, if_match[], apply[], raw
- `prefix_lists`: list of dicts with name, rules[] (index, action, prefix, mask_length, ge, le)
- `acls`: list of dicts with name/number, type, rules[] (action, source, destination, protocol, raw)
- `as_path_filters`: list of dicts with name, rules[] (action, pattern, raw) — merged by name
- `community_filters`: list of dicts with name, type, rules[] (index, action, value, raw) — merged by name, index optional

### Multicast Data Structures (`apps/parsers/huawei/parser.py`)
Stored in `parsed_data["multicast"]`:
- `ipv4_routing_enabled`: bool — `multicast routing-enable`
- `ipv6_routing_enabled`: bool — `multicast ipv6 routing-enable`
- `pim`: dict with `global` (static_rps[], bsr_candidates[], rp_candidates[], mode) and `vpn_instances[]` (name) — parsed from `pim { ... }` blocks
- `igmp_snooping`: dict with `global_enabled` (bool), `vlans[]` (vlan_id, enabled, version, querier_enabled) — parsed from `igmp-snooping` lines
- `vpn_instances[]`: list of dicts with name — parsed from `multicast vpn-instance` blocks
Per-interface post-processing (`_enrich_multicast` in parser) adds: `pim_enabled`, `pim_mode`, `pim_hello_holdtime`, `igmp_enabled`, `igmp_version`, `igmp_static_groups[]`, `igmp_join_groups[]`, `igmp_limit`, `mld_enabled`, `mld_version`, `mld_static_groups[]`

### Multicast Utils (`apps/analysis/multicast_utils.py`)
- `build_multicast_summary()` returns counts of PIM/IGMP/MLD interfaces, groups, static RPs, snooping VLANs
- `build_multicast_dependency_map()` returns dependencies: PIM/IGMP/MLD interface lists, missing VPN-instance references

### Multicast Comparison (`apps/analysis/comparison.py`)
- `_compare_multicast(base_data, target_data)` returns:
```python
{
  "global": {"added": [], "removed": [], "changed": [{"key": "...", "before": ..., "after": ...}]},
  "pim": {"added": [{"name": ..., "mode": ...}], "removed": [...], "changed": [{"section": "global", "before": ..., "after": ...}, {"name": ..., "changes": {...}}]},
  "igmp": {"added": [], "removed": [], "changed": []},
  "igmp_snooping": {"added": [], "removed": [], "changed": []},
  "mld": {"added": [], "removed": [], "changed": []},
  "vpn_instances": {"added": [], "removed": [], "changed": []}
}
```
- `_build_multicast_impacts()` generates impact descriptions from the diff dict
- Validation/rollback plans only added when `_has_multicast_changes()` returns True (before == after → no plans)

### Multicast Issues (`apps/analysis/detectors/issues.py`)
11 issue codes in `_detect_multicast_issues()`:
```python
pim_without_multicast_routing       # high: PIM interface without global routing-enable
igmp_without_multicast_routing      # medium: IGMP interface without routing-enable
mld_without_ipv6_multicast_routing  # medium: MLD interface without IPv6 routing-enable
pim_without_rp_or_bsr              # medium: PIM sparse-mode without RP/BSR
pim_static_rp_not_local            # low: RP IP not found on any local interface
igmp_snooping_without_querier      # low: snooping VLAN without querier
igmp_version_1                     # low: deprecated IGMP version
pim_interface_missing_description  # low: PIM interface without description
multicast_vpn_instance_not_found   # high: multicast references nonexistent VPN
igmp_invalid_group_address         # medium: not in 224.0.0.0/4 range
mld_invalid_group_address          # medium: does not start with ff
```

### Multicast Services (`apps/analysis/detectors/services.py`)
5 service types: `MULTICAST`, `PIM`, `IGMP`, `IGMP_SNOOPING`, `MLD`
- Metadata includes routing flags, interface counts, static RPs, groups, VLANs

### Documentation System (`apps/analysis/documentation.py`)
- `generate_analysis_documentation()` returns structured dict with all sections including `multicast`
- `_document_multicast_section()` generates PIM global/RPs/interfaces, IGMP/MLD interfaces, IGMP snooping VLANs
- Template at `templates/analysis/documentation.html` renders multicast section with routing badges, PIM/IGMP/MLD tables, snooping VLANs

### Template Structure
- `templates/analysis/search.html` — renders all 12 search sections with evidence, badges, and links (includes `Multicast / PIM / IGMP / MLD` section)
- `templates/analysis/documentation.html` — renders structured technical documentation with multicast section (PIM global/RPs, PIM interfaces table, IGMP interfaces table, MLD interfaces table, snooping VLANs table)
- `templates/analysis/comparison_detail.html` — renders comparison with multicast section showing PIM/IGMP/MLD/snooping/VPN changes
- Policy section in search template uses colored badges per type

### Test File: `apps/analysis/tests/test_multicast.py`
47 tests covering: parser (routing, PIM, IGMP, MLD, snooping), services (all 5 types + metadata), search (PIM, IGMP, MLD, group IP → web), web (detail, documentation, search, comparison), comparison (diff_data key, PIM/IGMP changes, impacts, validation/rollback), issues (11 individual codes + severity checks + before==after conditional)

## Common Workflows

### Adding a new search type
1. Add data extraction in `_search_policies()` or create a new `_search_*()` function
2. Register in `global_network_search()` return dict
3. Add to summary in `global_network_search()`
4. Add CLI display section in `apps/analysis/management/commands/network_search.py`
5. Add template section in `templates/analysis/search.html`
6. Add tests in `apps/analysis/tests/test_policy_integration.py` (or dedicated file)
7. Add web tests checking actual HTML content (not just 200 status)

### Adding a new multicast feature (e.g. MSDP)
1. Add parsing in `apps/parsers/huawei/parser.py` `_parse_multicast_block()` and `_enrich_multicast()`
2. Add issue codes in `apps/analysis/detectors/issues.py` `_detect_multicast_issues()`
3. Add service detection in `apps/analysis/detectors/services.py`
4. Add service type in `apps/analysis/models.py` `DetectedService.ServiceType`
5. Add documentation in `apps/analysis/documentation.py` `_document_multicast_section()`
6. Add search in `apps/analysis/search.py` `_search_multicast()`
7. Add comparison in `apps/analysis/comparison.py` `_compare_multicast()` + `_build_multicast_impacts()`
8. Add samples in `sample_configs/` (basic, risky, change_before, change_after)
9. Add tests in `apps/analysis/tests/test_multicast.py`
10. Run `python manage.py makemigrations && python manage.py migrate`

### Running searches
```powershell
# CLI
python manage.py network_search "EXPORT-CLIENTE"
python manage.py network_search "acl 3001"
python manage.py network_search "as-path-filter 10"
python manage.py network_search "200.200.200.0/30"
python manage.py network_search "multicast"
python manage.py network_search "pim"
python manage.py network_search "239.1.1.1"
python manage.py network_search "ff3e::1"

# Web: http://127.0.0.1:8000/search/?q=EXPORT-CLIENTE
```

### Running tests
```powershell
# All tests (1232)
python manage.py test

# Multicast-specific
python manage.py test apps.analysis.tests.test_multicast

# Policy-specific
python manage.py test apps.analysis.tests.test_policy_integration
python manage.py test apps.analysis.tests.test_policy

# Search-specific
python manage.py test apps.analysis.tests.test_search

# Parser-specific
python manage.py test apps.parsers.huawei.tests

# Collector-specific
python manage.py test apps.collector

# CLI commands (Fase 1 — dry-run only)
python manage.py discover_network --profile "Rede Matriz" --dry-run
python manage.py collect_device_configs --profile "Rede Matriz" --dry-run
python manage.py run_collector --profile "Rede Matriz" --dry-run
```

## Collector Architecture (Fase 1)

### App: `apps/collector/`

**4 modelos**:
- `NetworkCredential` — credenciais criptografadas (Fernet) para SSH/SNMP
- `DiscoveryProfile` — configuração de varredura (subnets, timeout, workers)
- `CollectorRun` — execução completa (status, contadores, summary)
- `CollectorTask` — cada etapa da execução (SNMP discovery, SSH collect, analyze)

### Adaptadores mockáveis

| Classe | Responsabilidade | Status |
|---|---|---|
| `BaseSnmpAdapter` | Interface para descoberta SNMP | Abstrata |
| `MockSnmpAdapter` | Retorna dados mock da tabela `MOCK_DISCOVERY_TABLE` | Implementado |
| `RealSnmpAdapter` | PySNMP real | Stub (Fase 2) |
| `BaseSshCollectorAdapter` | Interface para coleta SSH | Abstrata |
| `MockSshCollectorAdapter` | Retorna sample configs (Huawei/Cisco) | Implementado |
| `RealSshCollectorAdapter` | Netmiko real | Stub (Fase 3) |

### Segurança
- `security.py`: Fernet encrypt/decrypt via `COLLECTOR_SECRET_KEY` env
- `mask_secret()` / `mask_text()` — nunca expõe secrets em logs
- Fallback sem criptografia em dev (com warning)

### Dependências adicionadas
- `cryptography` — Fernet para criptografia de credenciais
- `netmiko` e `pysnmp` serão adicionados nas Fases 2/3

### Fase 2 (implementada — SNMP discovery real com PySNMP)
- `RealSnmpAdapter` implementado com PySNMP (`pysnmp>=4.2`)
- Lê OIDs: `sysDescr` (1.3.6.1.2.1.1.1.0), `sysObjectID` (1.3.6.1.2.1.1.2.0), `sysName` (1.3.6.1.2.1.1.5.0)
- `expand_cidr()` com `ipaddress` module, subnet safety (máx /24 por padrão)
- `validate_subnet_size()` com flag `--allow-large-subnet`
- Community resolvida: profile → credential
- Device deduplicado por IP → name
- `discover_network` e `run_collector` com SNMP real (sem dry-run)

### Fase 3 (implementada — SSH real com Netmiko)
- `RealSshCollectorAdapter` implementado com Netmiko (`netmiko>=4.0`)
- Conecta por vendor: Huawei (display current-configuration), Cisco (show running-config), ZTE (show running-config)
- Descriptografa senhas via Fernet antes de conectar
- `ConfigSnapshot(source="auto")` criado a partir da coleta
- `analyze=True` opcional: chama `analyze_config_snapshot()` do pipeline existente
- `device.last_collected_at` atualizado automaticamente
- Secrets mascarados em erros/logs; senha nunca vaza

### Fase 4 (implementada — Web UI read-only)
- Páginas: dashboard, run_list, run_detail, task_list, task_detail, profile_list, profile_detail, device_status
- Rotas sob `/collector/` com namespace `collector:`
- Sidebar com grupo "Coleta" (Collector, Execuções, Status)
- Dashboard principal com seção "Coleta automática"
- Todas as views exigem login (LoginRequiredMixin)
- Secrets/communities nunca aparecem nos templates
- Logs e erros mascarados

### Próximas fases
- **Fase 5**: Celery/Redis para coleta assíncrona + agendamento
- **Fase 4**: Web UI read-only (listagem de CollectorRun)
- **Fase 5**: Celery/Redis para coleta assíncrona + agendamento
