"""Utilitário para análise de VRF/VPN-instance e L3VPN.

Fornece funções para construir sumário de VRF, mapa de dependências
e detecção de issues específicas de VRF/L3VPN.
"""

from __future__ import annotations


def build_vrf_summary(parsed_data: dict) -> dict | None:
    """Build a summary of all VRF/VPN-instances with their key attributes.

    Args:
        parsed_data: Dicionário retornado pelo parser.

    Returns:
        Dict with 'vrfs' list and 'vpnv4_peers' list, or None if no VRF data.
    """
    vpn_instances = parsed_data.get("vpn_instances", [])
    if not vpn_instances:
        return None

    vrfs = []
    for vi in vpn_instances:
        name = vi.get("name", "")
        description = vi.get("description")
        af_data = vi.get("address_families", {})

        # Collect RD and RTs from all address families
        rd = None
        rt_import: list[str] = []
        rt_export: list[str] = []
        for af_name, af in af_data.items():
            if af.get("route_distinguisher"):
                rd = af["route_distinguisher"]
            for vt in af.get("vpn_targets", []):
                if vt["direction"] == "import" and vt["value"] not in rt_import:
                    rt_import.append(vt["value"])
                if vt["direction"] == "export" and vt["value"] not in rt_export:
                    rt_export.append(vt["value"])

        vrf_entry = {
            "name": name,
            "description": description,
            "rd": rd,
            "rt_import": rt_import,
            "rt_export": rt_export,
            "interfaces": [],
            "static_routes": [],
            "bgp_ipv4_family": False,
            "bgp_peers": [],
            "route_policies": [],
        }

        # Find interfaces bound to this VPN-instance
        for iface in parsed_data.get("interfaces", []):
            if iface.get("vpn_instance") == name:
                vrf_entry["interfaces"].append(iface["name"])

        # Find static routes in this VPN-instance
        for route in parsed_data.get("static_routes", []):
            if route.get("vpn_instance") == name:
                vrf_entry["static_routes"].append(
                    f"{route.get('network', '?')}/{route.get('netmask', '?')}"
                )

        # Find BGP ipv4-family vpn-instance data
        for bgp in parsed_data.get("bgp", []):
            for vi in bgp.get("vpn_instances", []):
                if vi["name"] == name:
                    vrf_entry["bgp_ipv4_family"] = True
                    for peer in vi.get("peers", []):
                        vrf_entry["bgp_peers"].append(peer["ip"])
                        if peer.get("route_policy_import"):
                            vrf_entry["route_policies"].append(peer["route_policy_import"])
                        if peer.get("route_policy_export"):
                            vrf_entry["route_policies"].append(peer["route_policy_export"])
                    break

        vrfs.append(vrf_entry)

    # Collect VPNv4 peers
    vpnv4_peers: list[str] = []
    for bgp in parsed_data.get("bgp", []):
        for vp in bgp.get("vpnv4", {}).get("peers", []):
            if vp.get("peer") and vp["peer"] not in vpnv4_peers:
                vpnv4_peers.append(vp["peer"])

    return {
        "vrfs": vrfs,
        "vpnv4_peers": vpnv4_peers,
        "total_vrfs": len(vrfs),
        "total_vpnv4_peers": len(vpnv4_peers),
    }


def build_vrf_dependency_map(parsed_data: dict) -> dict:
    """Build a dependency map relating VPN-instances to their components.

    Returns:
        Dict with keys: vrf_deps (list per VRF), duplicate_rds (list),
        vrfs_without_interfaces (list), vrfs_without_routes (list).
    """
    summary = build_vrf_summary(parsed_data)
    if not summary:
        return {
            "vrf_deps": [],
            "duplicate_rds": [],
            "vrfs_without_interfaces": [],
            "vrfs_without_routes": [],
        }

    # Detect duplicate RDs
    rd_map: dict[str, list[str]] = {}
    for vrf in summary["vrfs"]:
        if vrf["rd"]:
            rd_map.setdefault(vrf["rd"], []).append(vrf["name"])

    duplicate_rds = [
        {"rd": rd, "vrfs": names}
        for rd, names in rd_map.items()
        if len(names) > 1
    ]

    vrfs_without_interfaces = [
        v["name"] for v in summary["vrfs"] if not v["interfaces"]
    ]
    vrfs_without_routes = [
        v["name"]
        for v in summary["vrfs"]
        if not v["static_routes"] and not v["bgp_ipv4_family"]
    ]

    return {
        "vrf_deps": summary["vrfs"],
        "duplicate_rds": duplicate_rds,
        "vrfs_without_interfaces": vrfs_without_interfaces,
        "vrfs_without_routes": vrfs_without_routes,
    }
