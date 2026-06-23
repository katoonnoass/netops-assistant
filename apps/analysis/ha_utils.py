"""HA / BFD / Graceful Restart / NSR analysis utilities."""

from __future__ import annotations


def build_ha_summary(parsed_data: dict) -> dict:
    """Build summary counts for HA/BFD/GR/NSR data."""
    ha = parsed_data.get("ha", {})
    bfd = ha.get("bfd", {})
    gr = ha.get("graceful_restart", {})
    nsr = ha.get("nsr", {})

    # Count BFD-protected items
    bgp_bfd = 0
    iface_bfd = 0
    igp_bfd = 0
    for bgp in parsed_data.get("bgp", []):
        for p in bgp.get("peers", []):
            if p.get("bfd_enabled"):
                bgp_bfd += 1
    for iface in parsed_data.get("interfaces", []):
        if iface.get("isis_bfd_enabled") or iface.get("ospf_bfd_enabled") or iface.get("isis_ipv6_bfd_enabled") or iface.get("mpls_ldp_bfd_enabled"):
            iface_bfd += 1

    # Count IGP processes with BFD
    for ospf in parsed_data.get("ospf", []):
        if ospf.get("bfd_all_interfaces"):
            igp_bfd += 1
    for isis in parsed_data.get("isis", []):
        if isis.get("bfd_all_interfaces"):
            igp_bfd += 1

    return {
        "bfd_global": bfd.get("global_enabled", False),
        "bfd_sessions": len(bfd.get("sessions", [])),
        "bgp_peers_with_bfd": bgp_bfd,
        "interfaces_with_bfd": iface_bfd,
        "igp_with_bfd": igp_bfd,
        "graceful_restart": {k: v for k, v in gr.items() if v},
        "nsr": {k: v for k, v in nsr.items() if v},
    }


def build_ha_dependency_map(parsed_data: dict) -> dict:
    """Build dependency map for HA/BFD/GR/NSR features.

    Returns:
        dict with keys: bfd_sessions, protocol_bindings, graceful_restart, nsr
    """
    ha = parsed_data.get("ha", {})
    bfd = ha.get("bfd", {})
    interfaces = parsed_data.get("interfaces", [])

    # Build protocol bindings
    protocol_bindings = []

    # BGP peers with BFD
    for bgp in parsed_data.get("bgp", []):
        for p in bgp.get("peers", []):
            if p.get("bfd_enabled"):
                protocol_bindings.append({
                    "protocol": "bgp",
                    "peer": p.get("ip"),
                    "bfd_enabled": True,
                    "bfd_timers": p.get("bfd_timers"),
                    "graceful_restart": p.get("graceful_restart", False),
                })

    # ISIS processes with BFD
    for isis in parsed_data.get("isis", []):
        if isis.get("bfd_all_interfaces"):
            protocol_bindings.append({
                "protocol": "isis",
                "process_id": isis.get("process_id"),
                "bfd_enabled": True,
                "bfd_mode": "all-interfaces",
                "graceful_restart": isis.get("graceful_restart", False),
                "nsr_enabled": isis.get("nsr_enabled", False),
            })

    # OSPF processes with BFD
    for ospf in parsed_data.get("ospf", []):
        if ospf.get("bfd_all_interfaces"):
            protocol_bindings.append({
                "protocol": "ospf",
                "process_id": ospf.get("process_id"),
                "bfd_enabled": True,
                "bfd_mode": "all-interfaces",
                "graceful_restart": ospf.get("graceful_restart", False),
                "nsr_enabled": ospf.get("nsr_enabled", False),
            })

    # Interfaces with BFD per-protocol
    for iface in interfaces:
        name = iface.get("name", "")
        if iface.get("isis_bfd_enabled"):
            protocol_bindings.append({
                "protocol": "isis",
                "interface": name,
                "bfd_enabled": True,
                "bfd_mode": "interface",
            })
        if iface.get("ospf_bfd_enabled"):
            protocol_bindings.append({
                "protocol": "ospf",
                "interface": name,
                "bfd_enabled": True,
                "bfd_mode": "interface",
            })
        if iface.get("mpls_ldp_bfd_enabled"):
            protocol_bindings.append({
                "protocol": "ldp",
                "interface": name,
                "bfd_enabled": True,
                "bfd_mode": "interface",
            })

    missing_references = []

    # Check BFD sessions reference existing interfaces
    bfd_iface_names = {i["name"] for i in interfaces}
    for s in bfd.get("sessions", []):
        iface_ref = s.get("interface", "")
        if iface_ref and iface_ref not in bfd_iface_names:
            missing_references.append({
                "type": "bfd_session_interface_not_found",
                "name": s.get("name", ""),
                "referenced_by": iface_ref,
            })

    return {
        "bfd_sessions": bfd.get("sessions", []),
        "protocol_bindings": protocol_bindings,
        "graceful_restart": ha.get("graceful_restart", {}),
        "nsr": ha.get("nsr", {}),
        "missing_references": missing_references,
    }
