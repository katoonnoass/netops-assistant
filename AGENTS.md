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
- `global_network_search()` is the single entry point; returns 11 sections including `policies`
- `_search_policies()` searches route-policies, ip-prefixes, ACLs, as-path-filters, community-filters, and BGP policy dependencies
- Smart matching strips common prefixes (`acl `, `route-policy `, `ip-prefix `, `as-path-filter `, `community-filter `) for broader results
- Generic type-only queries (`route-policy`, `ip-prefix`, `acl`) match ALL items of that type
- Evidence is extracted from raw config text via `_get_evidence_lines()` with ±2 lines context
- Query classification handles: ip, prefix, vlan, interface, asn, text types
- CLI `python manage.py network_search "<query>"` now displays policies section

### Policy Data Structures (`apps/parsers/huawei/parser.py`)
All stored in `parsed_data` dict:
- `route_policies`: list of dicts with name, node, action, if_match[], apply[], raw
- `prefix_lists`: list of dicts with name, rules[] (index, action, prefix, mask_length, ge, le)
- `acls`: list of dicts with name/number, type, rules[] (action, source, destination, protocol, raw)
- `as_path_filters`: list of dicts with name, rules[] (action, pattern, raw) — merged by name
- `community_filters`: list of dicts with name, type, rules[] (index, action, value, raw) — merged by name, index optional

### Policy Dependencies (`apps/analysis/policy_utils.py`)
- `build_policy_reference_map()` builds: BGP peer → route-policy → ip-prefix/ACL/as-path/community
- `find_policy_issues()` detects: orphan policies, permit-any, missing filters, etc.
- Dependency chain is used by search, documentation, and comparison

### Documentation System (`apps/analysis/documentation.py`)
- `generate_analysis_documentation()` returns structured dict with all sections
- `_build_policy_documentation()` handles route-policies, ip-prefixes, ACLs, as-path/community filters, dependencies, orphans
- Community-filter rules include optional `index` field
- Template at `templates/analysis/documentation.html` renders policies section with badges

### Template Structure
- `templates/analysis/search.html` — renders all 11 search sections with evidence, badges, and links
- `templates/analysis/documentation.html` — renders structured technical documentation
- Policy section in search template uses colored badges per type (route_policy=#e91e63, ip_prefix=#9c27b0, acl=#ff5722, as_path_filter=#009688, community_filter=#00bcd4, bgp_policy_dependency=#ff9800)

## Common Workflows

### Adding a new search type
1. Add data extraction in `_search_policies()` or create a new `_search_*()` function
2. Register in `global_network_search()` return dict
3. Add to summary in `global_network_search()`
4. Add CLI display section in `apps/analysis/management/commands/network_search.py`
5. Add template section in `templates/analysis/search.html`
6. Add tests in `apps/analysis/tests/test_policy_integration.py` (or dedicated file)
7. Add web tests checking actual HTML content (not just 200 status)

### Running searches
```powershell
# CLI
python manage.py network_search "EXPORT-CLIENTE"
python manage.py network_search "acl 3001"
python manage.py network_search "as-path-filter 10"
python manage.py network_search "200.200.200.0/30"

# Web: http://127.0.0.1:8000/search/?q=EXPORT-CLIENTE
```

### Running tests
```powershell
# All tests
python manage.py test

# Policy-specific
python manage.py test apps.analysis.tests.test_policy_integration
python manage.py test apps.analysis.tests.test_policy

# Search-specific
python manage.py test apps.analysis.tests.test_search

# Parser-specific
python manage.py test apps.parsers.huawei.tests
```
