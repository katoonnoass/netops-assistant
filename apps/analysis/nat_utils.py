"""Utilitário para análise de NAT / PAT / Port Forward.

Fornece funções para construir sumário de NAT, mapa de dependências
e detecção de issues específicas de NAT.
"""

from __future__ import annotations


def build_nat_summary(parsed_data: dict) -> dict | None:
    """Build a summary of all NAT configuration in parsed data."""
    nat = parsed_data.get("nat", {})
    if not nat:
        return None
    if not any([nat.get("address_groups"), nat.get("outbound_rules"),
                nat.get("static_rules"), nat.get("server_rules")]):
        return None

    interfaces_with_nat = [
        i["name"] for i in parsed_data.get("interfaces", [])
        if i.get("has_nat")
    ]

    return {
        "total_address_groups": len(nat.get("address_groups", [])),
        "total_outbound_rules": len(nat.get("outbound_rules", [])),
        "total_static_rules": len(nat.get("static_rules", [])),
        "total_server_rules": len(nat.get("server_rules", [])),
        "total_alg_protocols": len(nat.get("alg", [])),
        "interfaces_with_nat": interfaces_with_nat,
    }


def build_nat_dependency_map(parsed_data: dict) -> dict:
    """Build a dependency map for NAT components.

    Relates:
    - NAT outbound → ACL, address-group, interface, VPN
    - NAT static/server → inside/global IP, VPN
    - Detects orphan address-groups, missing ACLs, missing groups
    """
    nat = parsed_data.get("nat", {})
    acls = parsed_data.get("acls", [])
    acl_names = set()
    for a in acls:
        if a.get("name"):
            acl_names.add(a["name"])
        if a.get("number"):
            acl_names.add(a["number"])

    address_group_names = {ag["name"] for ag in nat.get("address_groups", [])}
    referenced_groups: set[str] = set()
    referenced_acls: set[str] = set()

    outbound_deps = []
    for ob in nat.get("outbound_rules", []):
        acl = ob.get("acl")
        ag = ob.get("address_group")
        acl_found = acl in acl_names if acl else True
        ag_found = ag in address_group_names if ag else True

        # Find which interface this NAT is applied on
        iface_name = None
        for iface in parsed_data.get("interfaces", []):
            for raw_line in iface.get("nat_outbound", []):
                if acl and acl in raw_line:
                    iface_name = iface["name"]
                    break

        if acl:
            referenced_acls.add(acl)
        if ag:
            referenced_groups.add(ag)

        vpn = None
        if iface_name:
            for iface in parsed_data.get("interfaces", []):
                if iface["name"] == iface_name:
                    vpn = iface.get("vpn_instance")
                    break

        outbound_deps.append({
            "acl": acl,
            "address_group": ag,
            "interface": iface_name,
            "vpn_instance": vpn,
            "acl_found": acl_found,
            "address_group_found": ag_found,
        })

    # Find address-groups referenced by outbound rules
    orphan_groups = sorted(address_group_names - referenced_groups)

    # Collect static/server rules
    static_rules = []
    for sr in nat.get("static_rules", []):
        static_rules.append({
            "protocol": sr.get("protocol"),
            "global_ip": sr.get("global_ip"),
            "inside_ip": sr.get("inside_ip"),
            "vpn_instance": sr.get("vpn_instance"),
        })

    server_rules = []
    for sv in nat.get("server_rules", []):
        server_rules.append({
            "protocol": sv.get("protocol"),
            "global_ip": sv.get("global_ip"),
            "global_port": sv.get("global_port"),
            "inside_ip": sv.get("inside_ip"),
            "inside_port": sv.get("inside_port"),
        })

    return {
        "outbound": outbound_deps,
        "static_rules": static_rules,
        "server_rules": server_rules,
        "address_groups": nat.get("address_groups", []),
        "orphan_address_groups": orphan_groups,
        "missing_acls": sorted(acl for ob in outbound_deps if not ob["acl_found"] and ob["acl"]),
        "missing_address_groups": sorted(ag for ob in outbound_deps if not ob["address_group_found"] and ob["address_group"]),
    }
