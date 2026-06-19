"""
Policy utilities for Huawei VRP route-policy, ip-prefix, and ACL dependency mapping.

Provides deterministic analysis of the relationship between:
    BGP peer → route-policy → ip-prefix / ACL / as-path-filter / community-filter

These utilities are called from comparison, search, issues, and documentation modules.
"""

from __future__ import annotations

from typing import Any


def build_policy_reference_map(parsed_data: dict) -> dict:
    """Build a complete dependency map of BGP → route-policy → ip-prefix/ACL/filters.

    Args:
        parsed_data: The structured output from HuaweiVRPParser.parse()

    Returns:
        dict with keys:
            - bgp_peer_policies: list of peer → policy relationships
            - orphan_route_policies: route-policies not referenced by any BGP peer
            - orphan_ip_prefixes: ip-prefixes not referenced by any route-policy
            - policy_references: dict mapping each route-policy name → its dependencies
    """
    route_policies = {rp["name"]: rp for rp in parsed_data.get("route_policies", [])}
    ip_prefixes = {pp["name"]: pp for pp in parsed_data.get("prefix_lists", [])}
    as_path_filters = {af["name"]: af for af in parsed_data.get("as_path_filters", [])}
    community_filters = {cf["name"]: cf for cf in parsed_data.get("community_filters", [])}
    bgp_blocks = parsed_data.get("bgp", [])

    # Track which policies/prefixes are referenced
    referenced_policies: set[str] = set()
    referenced_prefixes: set[str] = set()
    referenced_as_path: set[str] = set()
    referenced_community: set[str] = set()

    # Build route-policy → dependencies map
    policy_refs: dict[str, dict] = {}
    for rp_name, rp in route_policies.items():
        deps: dict = {"ip_prefixes": [], "acls": [], "as_path_filters": [], "community_filters": []}
        for im in rp.get("if_match", []):
            im_type = im.get("type", "")
            im_name = im.get("name", "")
            if im_type == "ip-prefix":
                deps["ip_prefixes"].append(im_name)
                referenced_prefixes.add(im_name)
            elif im_type == "acl":
                deps["acls"].append(im_name)
            elif im_type == "as-path-filter":
                deps["as_path_filters"].append(im_name)
                referenced_as_path.add(im_name)
            elif im_type == "community-filter":
                deps["community_filters"].append(im_name)
                referenced_community.add(im_name)
        policy_refs[rp_name] = deps

    # Build BGP peer → policy mapping
    bgp_peer_policies: list[dict] = []
    for bgp in bgp_blocks:
        for peer in bgp.get("peers", []):
            for direction in ("import", "export"):
                pname = peer.get(f"route_policy_{direction}")
                if pname:
                    bgp_peer_policies.append({
                        "peer": peer.get("ip", ""),
                        "direction": direction,
                        "route_policy": pname,
                        "found": pname in route_policies,
                        "dependencies": policy_refs.get(pname, {}),
                    })
                    referenced_policies.add(pname)

    # Orphan detection
    orphan_route_policies = sorted(
        n for n in route_policies if n not in referenced_policies
    )
    orphan_ip_prefixes = sorted(
        n for n in ip_prefixes if n not in referenced_prefixes
    )
    orphan_as_path_filters = sorted(
        n for n in as_path_filters if n not in referenced_as_path
    )
    orphan_community_filters = sorted(
        n for n in community_filters if n not in referenced_community
    )

    return {
        "bgp_peer_policies": bgp_peer_policies,
        "orphan_route_policies": orphan_route_policies,
        "orphan_ip_prefixes": orphan_ip_prefixes,
        "orphan_as_path_filters": orphan_as_path_filters,
        "orphan_community_filters": orphan_community_filters,
        "policy_references": policy_refs,
    }


def find_policy_issues(parsed_data: dict) -> list[dict]:
    """Find policy-related issues deterministically.

    Args:
        parsed_data: Structured output from HuaweiVRPParser.parse()

    Returns:
        list of issue dicts with keys: code, severity, title, description, metadata
    """
    issues: list[dict] = []
    route_policies = parsed_data.get("route_policies", [])
    ip_prefixes = parsed_data.get("prefix_lists", [])
    acls = parsed_data.get("acls", [])
    ref_map = build_policy_reference_map(parsed_data)

    # B. Route-policy permit without if-match
    for rp in route_policies:
        if rp.get("action") == "permit" and not rp.get("if_match"):
            issues.append({
                "code": "route_policy_permit_without_match",
                "severity": "medium",
                "title": "Route-policy permit sem if-match",
                "description": f"Route-policy {rp['name']} com ação permit sem condição if-match pode permitir rotas de forma ampla.",
                "metadata": {"policy_name": rp["name"], "node": rp.get("node")},
            })

    # C. Route-policy without apply
    for rp in route_policies:
        if not rp.get("apply"):
            issues.append({
                "code": "route_policy_without_apply",
                "severity": "low",
                "title": "Route-policy sem apply",
                "description": f"Route-policy {rp['name']} não possui ações apply. Deve ser validada.",
                "metadata": {"policy_name": rp["name"], "node": rp.get("node")},
            })

    # D. IP-prefix permit any
    for pp in ip_prefixes:
        for rule in pp.get("rules", []):
            if rule.get("action") != "permit":
                continue
            prefix = rule.get("prefix", "")
            mask = rule.get("mask_length", 0)
            le = rule.get("less_equal")
            if prefix == "0.0.0.0" and mask == 0 and le == 32:
                issues.append({
                    "code": "ip_prefix_permit_any",
                    "severity": "high",
                    "title": "IP-prefix permitindo qualquer rota",
                    "description": f"IP-prefix {pp['name']} com permit 0.0.0.0/0 less-equal 32 detectado.",
                    "metadata": {"prefix_name": pp["name"], "rule_index": rule.get("index")},
                })

    # E. ACL rule any
    for acl in acls:
        for rule in acl.get("rules", []):
            src = rule.get("source", "")
            dst = rule.get("destination", "")
            if not src and not dst:
                issues.append({
                    "code": "acl_rule_any",
                    "severity": "medium",
                    "title": "Regra ACL ampla detectada",
                    "description": f"ACL {acl.get('name', '?')} possui regra sem source nem destination. Validar se é intencional.",
                    "metadata": {"acl_name": acl.get("name"), "raw": rule.get("raw", "")},
                })
                break  # One issue per ACL is enough

    # F. Orphan route-policy
    for rp_name in ref_map.get("orphan_route_policies", []):
        issues.append({
            "code": "route_policy_orphan",
            "severity": "low",
            "title": "Route-policy sem referência detectada",
            "description": f"Route-policy {rp_name} criada mas não referenciada por BGP ou outra policy conhecida.",
            "metadata": {"policy_name": rp_name},
        })

    # G. Orphan ip-prefix
    for pp_name in ref_map.get("orphan_ip_prefixes", []):
        issues.append({
            "code": "ip_prefix_orphan",
            "severity": "low",
            "title": "IP-prefix sem referência detectado",
            "description": f"IP-prefix {pp_name} criado mas não referenciado por route-policy conhecida.",
            "metadata": {"prefix_name": pp_name},
        })

    # H. Missing as-path-filter referenced by route-policy
    as_path_filters_dict = {af["name"]: af for af in parsed_data.get("as_path_filters", [])}
    community_filters_dict = {cf["name"]: cf for cf in parsed_data.get("community_filters", [])}
    for rp in route_policies:
        for im in rp.get("if_match", []):
            if im.get("type") == "as-path-filter":
                fname = im.get("name", "")
                if fname not in as_path_filters_dict:
                    issues.append({
                        "code": "route_policy_as_path_filter_not_found",
                        "severity": "medium",
                        "title": "AS-path filter referenciado n\u00e3o encontrado",
                        "description": f"Route-policy {rp['name']} referencia as-path-filter {fname} que n\u00e3o foi localizado na configura\u00e7\u00e3o.",
                        "metadata": {"policy_name": rp["name"], "filter_name": fname},
                    })
            if im.get("type") == "community-filter":
                fname = im.get("name", "")
                if fname not in community_filters_dict:
                    issues.append({
                        "code": "route_policy_community_filter_not_found",
                        "severity": "medium",
                        "title": "Community-filter referenciado n\u00e3o encontrado",
                        "description": f"Route-policy {rp['name']} referencia community-filter {fname} que n\u00e3o foi localizado na configura\u00e7\u00e3o.",
                        "metadata": {"policy_name": rp["name"], "filter_name": fname},
                    })

    # J. Orphan as-path-filter
    for af_name in ref_map.get("orphan_as_path_filters", []):
        issues.append({
            "code": "as_path_filter_orphan",
            "severity": "low",
            "title": "AS-path filter sem refer\u00eancia detectado",
            "description": f"AS-path filter {af_name} criado mas n\u00e3o referenciado por route-policy conhecida.",
            "metadata": {"filter_name": af_name},
        })

    # K. Orphan community-filter
    for cf_name in ref_map.get("orphan_community_filters", []):
        issues.append({
            "code": "community_filter_orphan",
            "severity": "low",
            "title": "Community-filter sem refer\u00eancia detectado",
            "description": f"Community-filter {cf_name} criado mas n\u00e3o referenciado por route-policy conhecida.",
            "metadata": {"filter_name": cf_name},
        })

    # L. AS-path permit any
    for af in as_path_filters_dict.values():
        for rule in af.get("rules", []):
            if rule.get("action") == "permit" and rule.get("pattern") == ".*":
                issues.append({
                    "code": "as_path_filter_permit_any",
                    "severity": "medium",
                    "title": "AS-path filter permitindo qualquer AS",
                    "description": f"AS-path filter {af['name']} com permit .* detectado.\nPode permitir AS_PATHs n\u00e3o autorizados.",
                    "metadata": {"filter_name": af["name"]},
                })
                break

    return issues


def get_policy_service_info(parsed_data: dict) -> dict | None:
    """Determine if route-policy, ip-prefix, or ACL services are present.

    Returns a dict with service_type and metadata, or None if nothing detected.
    """
    route_policies = parsed_data.get("route_policies", [])
    ip_prefixes = parsed_data.get("prefix_lists", [])
    acls = parsed_data.get("acls", [])
    
    services: list[dict] = []
    
    if route_policies or ip_prefixes:
        services.append({
            "service_type": "route_policy",
            "name": "Políticas de Roteamento",
            "metadata": {
                "route_policy_count": len(route_policies),
                "ip_prefix_count": len(ip_prefixes),
                "acl_count": len(acls),
            },
        })
    
    if acls:
        services.append({
            "service_type": "acl_policy",
            "name": "ACL Policy",
            "metadata": {"acl_count": len(acls)},
        })
    
    # Check for BGP peers referencing policies
    ref_map = build_policy_reference_map(parsed_data)
    if ref_map.get("bgp_peer_policies"):
        for svc in services:
            svc["metadata"]["bgp_peers_with_policy"] = len(ref_map["bgp_peer_policies"])
    
    return services if services else None
