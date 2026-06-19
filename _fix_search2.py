"""Implement search policies integration."""

# =============================================================
# 1. Add _search_policies function to search.py  
# =============================================================
with open('apps/analysis/search.py', 'r', encoding='utf-8') as f:
    t = f.read()

# Find where _search_bgp ends and add _search_policies after it
# Find _search_bgp function end (next function after it)
import re
m = re.search(r'^def _search_bgp_peer_score\(', t, re.MULTILINE)
if m:
    insert_at = m.start()
    new_func = '''
def _search_policies(
    classification: dict, filters: dict | None, only_last_snapshot: bool = False
) -> list[dict]:
    """Search route-policies, ip-prefixes, ACLs, as-path/community filters."""
    q = classification["query"]
    qtype = classification["type"]
    qval = classification.get("value", q)
    q_upper = q.upper() if q else ""
    q_lower = q.lower() if q else ""

    parsed_qs = ParsedConfig.objects.select_related(
        "snapshot__device"
    ).all()

    if filters:
        if filters.get("vendor"):
            parsed_qs = parsed_qs.filter(snapshot__vendor=filters["vendor"])
        if filters.get("device"):
            parsed_qs = parsed_qs.filter(
                snapshot__device__name__icontains=filters["device"]
            )
        if filters.get("last_snapshot_only") or only_last_snapshot:
            from django.db.models import Max
            latest_ids = (
                parsed_qs.values("snapshot__device_id")
                .annotate(max_id=Max("pk"))
                .values_list("max_id", flat=True)
            )
            parsed_qs = parsed_qs.filter(pk__in=list(latest_ids))

    results: list[dict] = []
    for parsed in parsed_qs:
        pd = parsed.parsed_data
        device_name = parsed.snapshot.device.name if parsed.snapshot.device else ""
        device_pk = parsed.snapshot.device.pk if parsed.snapshot.device else None
        base_result = {
            "device": device_name,
            "device_pk": device_pk,
            "snapshot": parsed.snapshot.pk,
            "parsed_config": parsed.pk,
            "url": f"/analysis/{parsed.pk}/",
            "evidence": [],
        }

        # Route-policies
        for rp in pd.get("route_policies", []):
            rp_name = rp.get("name", "")
            if q_upper in rp_name.upper() or q_lower in rp_name.lower():
                results.append(dict(base_result, **{
                    "type": "route_policy",
                    "title": f"Route-policy: {rp_name}",
                    "description": f"Node {rp.get('node')} ({rp.get('action')})",
                    "score": 0.9,
                    "metadata": {"policy_name": rp_name, "node": rp.get("node")},
                }))

        # IP prefix-lists
        for pp in pd.get("prefix_lists", []):
            pp_name = pp.get("name", "")
            if q_upper in pp_name.upper():
                results.append(dict(base_result, **{
                    "type": "ip_prefix",
                    "title": f"IP prefix-list: {pp_name}",
                    "description": f"{len(pp.get('rules', []))} regra(s)",
                    "score": 0.9,
                    "metadata": {"prefix_name": pp_name},
                }))
            for rule in pp.get("rules", []):
                if q_lower in rule.get("prefix", ""):
                    results.append(dict(base_result, **{
                        "type": "ip_prefix",
                        "title": f"IP prefix-rule: {pp_name}",
                        "description": f"Index {rule.get('index')}: {rule.get('action')} {rule.get('prefix')}/{rule.get('mask_length')}",
                        "score": 0.85,
                        "metadata": {"prefix_name": pp_name, "rule": rule},
                    }))

        # ACLs
        for acl in pd.get("acls", []):
            acl_name = acl.get("name", "")
            if q_upper in acl_name.upper():
                results.append(dict(base_result, **{
                    "type": "acl",
                    "title": f"ACL: {acl_name}",
                    "description": f"{len(acl.get('rules', []))} regra(s)",
                    "score": 0.9,
                    "metadata": {"acl_name": acl_name, "acl_type": acl.get("type")},
                }))
            for rule in acl.get("rules", []):
                if q_lower in rule.get("raw", "").lower():
                    results.append(dict(base_result, **{
                        "type": "acl",
                        "title": f"ACL rule: {acl_name}",
                        "description": rule.get("raw", "")[:120],
                        "score": 0.8,
                        "metadata": {"acl_name": acl_name, "raw": rule.get("raw")},
                    }))

        # AS-path filters
        for af in pd.get("as_path_filters", []):
            af_name = af.get("name", "")
            if q_upper in af_name.upper():
                results.append(dict(base_result, **{
                    "type": "as_path_filter",
                    "title": f"AS-path filter: {af_name}",
                    "description": f"{len(af.get('rules', []))} regra(s)",
                    "score": 0.9,
                    "metadata": {"filter_name": af_name},
                }))
            for rule in af.get("rules", []):
                if q_lower in rule.get("pattern", "") or q_lower in rule.get("raw", "").lower():
                    results.append(dict(base_result, **{
                        "type": "as_path_filter",
                        "title": f"AS-path rule: {af_name}",
                        "description": f"{rule.get('action')} {rule.get('pattern')}",
                        "score": 0.85,
                        "metadata": {"filter_name": af_name, "rule": rule},
                    }))

        # Community filters
        for cf in pd.get("community_filters", []):
            cf_name = cf.get("name", "")
            if q_upper in cf_name.upper():
                results.append(dict(base_result, **{
                    "type": "community_filter",
                    "title": f"Community-filter: {cf_name}",
                    "description": f"{len(cf.get('rules', []))} regra(s) ({cf.get('type', 'basic')})",
                    "score": 0.9,
                    "metadata": {"filter_name": cf_name},
                }))
            for rule in cf.get("rules", []):
                if q_lower in rule.get("value", "") or q_lower in rule.get("raw", "").lower():
                    results.append(dict(base_result, **{
                        "type": "community_filter",
                        "title": f"Community rule: {cf_name}",
                        "description": f"Index {rule.get('index')} " if rule.get("index") else "" + f"{rule.get('action')} {rule.get('value')}",
                        "score": 0.85,
                        "metadata": {"filter_name": cf_name, "rule": rule},
                    }))

        # BGP peer → route-policy dependencies
        for bgp in pd.get("bgp", []):
            for peer in bgp.get("peers", []):
                for direction in ("import", "export"):
                    rp_name = peer.get(f"route_policy_{direction}")
                    if rp_name and (q_upper in rp_name.upper()):
                        results.append(dict(base_result, **{
                            "type": "bgp_policy_dependency",
                            "title": f"BGP peer {peer.get('ip')} {direction}: {rp_name}",
                            "description": f"AS {peer.get('remote_as')}",
                            "score": 0.8,
                            "metadata": {"peer": peer.get("ip"), "direction": direction, "route_policy": rp_name},
                        }))

    return results

'''
    t = t[:insert_at] + new_func + t[insert_at:]
    print("[OK] Added _search_policies function")
else:
    print("[ERROR] Could not find insertion point")

# Add call in global_network_search
old = '''    raw_matches = _search_raw_matches(classification, effective_filters)

    summary_counts: dict[str, int] = {'''
new = '''    raw_matches = _search_raw_matches(classification, effective_filters)
    policies = _search_policies(
        classification, effective_filters, only_last_snapshot
    )

    summary_counts: dict[str, int] = {'''
t = t.replace(old, new, 1)

# Add policies to summary counts
old = '''        "bgp_peers": len(bgp_peers),
        "raw_matches": len(raw_matches),'''
new = '''        "bgp_peers": len(bgp_peers),
        "policies": len(policies),
        "raw_matches": len(raw_matches),'''
t = t.replace(old, new, 1)

# Add policies to return dict
old = '''        "bgp_peers": bgp_peers,
        "raw_matches": raw_matches,'''
new = '''        "bgp_peers": bgp_peers,
        "policies": policies,
        "raw_matches": raw_matches,'''
t = t.replace(old, new, 1)

with open('apps/analysis/search.py', 'w', encoding='utf-8') as f:
    f.write(t)
print("[OK] search.py updated")
