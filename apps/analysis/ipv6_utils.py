"""IPv6 analysis utilities for Huawei/VRP configurations."""

from __future__ import annotations


def build_ipv6_summary(parsed_data: dict) -> dict:
    """Build a summary of IPv6-related configuration."""
    summary = {
        "total_ipv6_interfaces": 0,
        "total_ipv6_routes": 0,
        "total_ipv6_prefix_lists": 0,
        "total_bgp_ipv6_peers": 0,
        "total_bgp_ipv6_networks": 0,
        "total_vpnv6_peers": 0,
        "total_ipv6_vpn_instances": 0,
        "total_ospfv3_processes": 0,
        "total_isis_ipv6_interfaces": 0,
    }

    # Interfaces with IPv6
    for iface in parsed_data.get("interfaces", []):
        if iface.get("ipv6_enabled"):
            summary["total_ipv6_interfaces"] += 1
        if iface.get("isis_ipv6_enabled"):
            summary["total_isis_ipv6_interfaces"] += 1

    # Static routes
    summary["total_ipv6_routes"] = len(parsed_data.get("ipv6_static_routes", []))

    # IPv6 prefix-lists
    for pl in parsed_data.get("prefix_lists", []):
        if pl.get("is_ipv6"):
            summary["total_ipv6_prefix_lists"] += 1

    # BGP IPv6
    for bgp in parsed_data.get("bgp", []):
        ipv6 = bgp.get("ipv6_unicast", {})
        summary["total_bgp_ipv6_peers"] += len(ipv6.get("peers", []))
        summary["total_bgp_ipv6_networks"] += len(ipv6.get("networks", []))
        summary["total_vpnv6_peers"] += len(bgp.get("vpnv6", {}).get("peers", []))
        summary["total_ipv6_vpn_instances"] += len(bgp.get("vpn_instances_ipv6", []))

    # OSPFv3
    summary["total_ospfv3_processes"] = len(parsed_data.get("ospfv3", []))

    return summary


def build_ipv6_dependency_map(parsed_data: dict) -> dict:
    """Build a dependency map for IPv6 components.

    Returns:
        dict with keys:
            - ipv6_interfaces: list of interface names with IPv6
            - ipv6_routes: list of IPv6 routes
            - bgp_ipv6_peers: list of BGP IPv6 peer dicts
            - bgp_ipv6_networks: list of BGP IPv6 network strings
            - vpnv6_peers: list of VPNv6 peer dicts
            - ipv6_vpn_instances: list of VPN instance names with IPv6
            - ipv6_prefix_lists: list of IPv6 prefix-list names
            - route_policies_v6: list of route-policies with IPv6 if-match
            - ospfv3_processes: list of OSPFv3 process IDs
            - isis_ipv6_interfaces: list of interface names with ISIS IPv6
    """
    deps = {
        "ipv6_interfaces": [],
        "ipv6_routes": [],
        "bgp_ipv6_peers": [],
        "bgp_ipv6_networks": [],
        "vpnv6_peers": [],
        "ipv6_vpn_instances": [],
        "ipv6_prefix_lists": [],
        "route_policies_v6": [],
        "ospfv3_processes": [],
        "isis_ipv6_interfaces": [],
    }

    # Interfaces
    for iface in parsed_data.get("interfaces", []):
        if iface.get("ipv6_enabled"):
            deps["ipv6_interfaces"].append(iface["name"])
        if iface.get("isis_ipv6_enabled"):
            deps["isis_ipv6_interfaces"].append(iface["name"])

    # Routes
    deps["ipv6_routes"] = parsed_data.get("ipv6_static_routes", [])

    # BGP IPv6
    for bgp in parsed_data.get("bgp", []):
        ipv6 = bgp.get("ipv6_unicast", {})
        deps["bgp_ipv6_peers"].extend(ipv6.get("peers", []))
        deps["bgp_ipv6_networks"].extend(ipv6.get("networks", []))
        deps["vpnv6_peers"].extend(bgp.get("vpnv6", {}).get("peers", []))
        for vi in bgp.get("vpn_instances_ipv6", []):
            deps["ipv6_vpn_instances"].append(vi.get("name", ""))

    # IPv6 prefix-lists
    for pl in parsed_data.get("prefix_lists", []):
        if pl.get("is_ipv6"):
            deps["ipv6_prefix_lists"].append(pl["name"])

    # Route-policies with IPv6 if-match
    for rp in parsed_data.get("route_policies", []):
        for ifm in rp.get("if_match", []):
            if ifm.get("type") == "ipv6-prefix-list":
                deps["route_policies_v6"].append(rp["name"])
                break

    # OSPFv3
    for ospfv3 in parsed_data.get("ospfv3", []):
        deps["ospfv3_processes"].append(ospfv3.get("process_id", ""))

    return deps
