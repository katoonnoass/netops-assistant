"""Multicast / PIM / IGMP / MLD analysis utilities."""

from __future__ import annotations


def build_multicast_summary(parsed_data: dict) -> dict:
    """Build summary counts for multicast data."""
    mc = parsed_data.get("multicast", {})
    interfaces = parsed_data.get("interfaces", [])
    pim_ifaces = [i for i in interfaces if i.get("pim_enabled")]
    igmp_ifaces = [i for i in interfaces if i.get("igmp_enabled")]
    mld_ifaces = [i for i in interfaces if i.get("mld_enabled")]
    return {
        "ipv4_routing": mc.get("ipv4_routing_enabled", False),
        "ipv6_routing": mc.get("ipv6_routing_enabled", False),
        "pim_interfaces": len(pim_ifaces),
        "igmp_interfaces": len(igmp_ifaces),
        "mld_interfaces": len(mld_ifaces),
        "igmp_snooping_vlans": len(mc.get("igmp_snooping", {}).get("vlans", [])),
        "static_rps": [rp["rp_address"] for rp in mc.get("pim", {}).get("global", {}).get("static_rps", [])],
        "igmp_groups": list({g for i in igmp_ifaces for g in (i.get("igmp_static_groups", []) + i.get("igmp_join_groups", []))}),
        "mld_groups": list({g for i in mld_ifaces for g in i.get("mld_static_groups", [])}),
    }


def build_multicast_dependency_map(parsed_data: dict) -> dict:
    """Build dependency map for multicast features."""
    mc = parsed_data.get("multicast", {})
    interfaces = parsed_data.get("interfaces", [])
    vpn_names = {v.get("name") for v in parsed_data.get("vpn_instances", [])}

    pim_interfaces = []
    igmp_interfaces = []
    mld_interfaces = []
    missing_references = []

    for iface in interfaces:
        name = iface.get("name", "")
        if iface.get("pim_enabled"):
            pim_interfaces.append({"name": name, "mode": iface.get("pim_mode"), "hello_holdtime": iface.get("pim_hello_holdtime")})
        if iface.get("igmp_enabled"):
            igmp_interfaces.append({"name": name, "version": iface.get("igmp_version"), "static_groups": iface.get("igmp_static_groups", []), "join_groups": iface.get("igmp_join_groups", [])})
        if iface.get("mld_enabled"):
            mld_interfaces.append({"name": name, "version": iface.get("mld_version"), "static_groups": iface.get("mld_static_groups", [])})

    # Check PIM VPN-instance references
    for v in mc.get("pim", {}).get("vpn_instances", []):
        if v["name"] and v["name"] not in vpn_names:
            missing_references.append({"type": "multicast_vpn_instance_not_found", "name": v["name"], "referenced_by": "pim"})

    return {
        "ipv4_routing": mc.get("ipv4_routing_enabled", False),
        "ipv6_routing": mc.get("ipv6_routing_enabled", False),
        "pim_global": mc.get("pim", {}).get("global", {}),
        "pim_interfaces": pim_interfaces,
        "igmp_interfaces": igmp_interfaces,
        "mld_interfaces": mld_interfaces,
        "igmp_snooping": mc.get("igmp_snooping", {}),
        "missing_references": missing_references,
    }
