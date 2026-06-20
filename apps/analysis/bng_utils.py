"""BNG/AAA/RADIUS/IP pool analysis utilities."""

from __future__ import annotations


def build_bng_summary(parsed_data: dict) -> dict:
    """Build a summary of BNG/AAA/RADIUS/IP pool configuration."""
    summary = {
        "total_bas_interfaces": 0,
        "total_domains": 0,
        "total_aaa_schemes": 0,
        "total_radius_groups": 0,
        "total_ip_pools": 0,
        "total_authentication_servers": 0,
        "total_accounting_servers": 0,
    }

    # BAS interfaces
    ifaces = parsed_data.get("interfaces", [])
    for iface in ifaces:
        if iface.get("bas") and iface["bas"].get("enabled"):
            summary["total_bas_interfaces"] += 1

    # Domains
    aaa_blocks = parsed_data.get("aaa", [])
    domains_in_aaa = set()
    for ab in aaa_blocks:
        for d in ab.get("domains", []):
            domains_in_aaa.add(d["name"])
    standalone_domains = {d["name"] for d in parsed_data.get("aaa_domains", [])}
    summary["total_domains"] = len(domains_in_aaa | standalone_domains)

    # AAA schemes
    for ab in aaa_blocks:
        summary["total_aaa_schemes"] += len(ab.get("authentication_schemes", []))
        summary["total_aaa_schemes"] += len(ab.get("accounting_schemes", []))
        summary["total_aaa_schemes"] += len(ab.get("authorization_schemes", []))

    # RADIUS groups
    summary["total_radius_groups"] = len(parsed_data.get("radius_servers", []))
    for rs in parsed_data.get("radius_servers", []):
        summary["total_authentication_servers"] += len(rs.get("authentication_servers", []))
        summary["total_accounting_servers"] += len(rs.get("accounting_servers", []))

    # IP pools
    summary["total_ip_pools"] = len(parsed_data.get("ip_pools", []))

    return summary


def build_bng_dependency_map(parsed_data: dict) -> dict:
    """Build a dependency map for BNG/AAA components.

    Returns dict with:
        - bas_interfaces: list of interface names with BAS
        - domains: list of domain names
        - radius_groups: list of RADIUS group names
        - ip_pools: list of IP pool names
        - missing_references: list of dicts with type/name/referenced_by
    """
    deps = {
        "bas_interfaces": [],
        "domains": [],
        "radius_groups": [],
        "ip_pools": [],
        "missing_references": [],
    }

    # Collect all domain names
    all_domains = set()
    aaa_blocks = parsed_data.get("aaa", [])
    for ab in aaa_blocks:
        for d in ab.get("domains", []):
            all_domains.add(d["name"])
    for d in parsed_data.get("aaa_domains", []):
        all_domains.add(d["name"])
    deps["domains"] = list(all_domains)

    # Collect RADIUS group names
    all_radius = {r["name"] for r in parsed_data.get("radius_servers", [])}
    deps["radius_groups"] = list(all_radius)

    # Collect IP pool names
    all_pools = {p["name"] for p in parsed_data.get("ip_pools", [])}
    deps["ip_pools"] = list(all_pools)

    # BAS interfaces and their dependencies
    for iface in parsed_data.get("interfaces", []):
        bas = iface.get("bas")
        if bas and bas.get("enabled"):
            entry = {
                "interface": iface["name"],
                "default_domain": bas.get("default_domain"),
                "authentication_method": bas.get("authentication_method"),
                "user_vlan": iface.get("user_vlan"),
                "description": iface.get("description"),
            }
            deps["bas_interfaces"].append(entry)

            # Check domain references in BAS
            dom = bas.get("default_domain")
            if dom and dom not in all_domains:
                deps["missing_references"].append({
                    "type": "domain",
                    "name": dom,
                    "referenced_by": f"BAS interface {iface['name']}",
                })

            # Check accounting-copy radius group
            acct_copy = bas.get("accounting_copy_radius_group")
            if acct_copy and acct_copy not in all_radius:
                deps["missing_references"].append({
                    "type": "radius_group",
                    "name": acct_copy,
                    "referenced_by": f"BAS interface {iface['name']} (accounting-copy)",
                })

    # Check domain references to schemes, groups, pools
    all_domains_list = []
    for ab in aaa_blocks:
        all_domains_list.extend(ab.get("domains", []))
    all_domains_list.extend(parsed_data.get("aaa_domains", []))

    for d in all_domains_list:
        name = d["name"]
        auth_scheme = d.get("authentication_scheme")
        acct_scheme = d.get("accounting_scheme")
        authz_scheme = d.get("authorization_scheme")
        radius_group = d.get("radius_server_group")
        ip_pool = d.get("ip_pool")

        all_auth = set()
        all_acct = set()
        all_authz = set()
        for ab in aaa_blocks:
            for s in ab.get("authentication_schemes", []):
                all_auth.add(s["name"])
            for s in ab.get("accounting_schemes", []):
                all_acct.add(s["name"])
            for s in ab.get("authorization_schemes", []):
                all_authz.add(s["name"])

        if auth_scheme and auth_scheme not in all_auth:
            deps["missing_references"].append({
                "type": "auth_scheme", "name": auth_scheme, "referenced_by": f"domain {name}",
            })
        if acct_scheme and acct_scheme not in all_acct:
            deps["missing_references"].append({
                "type": "acct_scheme", "name": acct_scheme, "referenced_by": f"domain {name}",
            })
        if authz_scheme and authz_scheme not in all_authz:
            deps["missing_references"].append({
                "type": "authz_scheme", "name": authz_scheme, "referenced_by": f"domain {name}",
            })
        if radius_group and radius_group not in all_radius:
            deps["missing_references"].append({
                "type": "radius_group", "name": radius_group, "referenced_by": f"domain {name}",
            })
        if ip_pool and ip_pool not in all_pools:
            deps["missing_references"].append({
                "type": "ip_pool", "name": ip_pool, "referenced_by": f"domain {name}",
            })

    return deps
