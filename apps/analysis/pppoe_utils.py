"""PPPoE / Virtual-Template / PPP analysis utilities."""

from __future__ import annotations


def build_pppoe_summary(parsed_data: dict) -> dict:
    """Build summary counts for PPPoE and Virtual-Template data."""
    pppoe_data = parsed_data.get("pppoe", {})
    interfaces = parsed_data.get("interfaces", [])
    vts = pppoe_data.get("virtual_templates", [])
    pppoe_ifaces = pppoe_data.get("pppoe_interfaces", [])

    # Also count from per-interface data
    pppoe_interface_count = sum(
        1 for i in interfaces
        if i.get("pppoe_server", {}).get("enabled")
    )
    vt_interface_count = sum(
        1 for i in interfaces
        if i.get("name", "").lower().startswith("virtual-template")
    )

    total_max_sessions = sum(
        (i.get("pppoe_server") or {}).get("max_sessions", 0) or 0
        for i in interfaces
    )

    ppp_modes_used = set()
    for i in interfaces:
        for mode in i.get("ppp_authentication_modes", []):
            ppp_modes_used.add(mode.lower())

    return {
        "total_pppoe_interfaces": pppoe_interface_count,
        "total_virtual_templates": vt_interface_count,
        "total_max_sessions": total_max_sessions,
        "total_ppp_auth_modes": len(ppp_modes_used),
        "ppp_auth_modes": sorted(ppp_modes_used),
        "virtual_templates": [vt["name"] for vt in vts],
        "pppoe_interfaces": [pi["interface"] for pi in pppoe_ifaces],
    }


def build_pppoe_dependency_map(parsed_data: dict) -> dict:
    """Build dependency map for PPPoE → Virtual-Template → AAA/RADIUS/IP pool.

    Returns:
        dict with keys:
            pppoe_interfaces: list of PPPoE interface details
            virtual_templates: list of Virtual-Template details
            missing_references: list of dicts with type/name/referenced_by
    """
    interfaces = parsed_data.get("interfaces", [])
    pppoe_data = parsed_data.get("pppoe", {})
    vts = pppoe_data.get("virtual_templates", [])
    vt_names = {vt["name"] for vt in vts}

    pppoe_interfaces = []
    missing_references = []

    for iface in interfaces:
        pppoe = iface.get("pppoe_server")
        if not pppoe or not pppoe.get("enabled"):
            continue

        vt_ref = pppoe.get("virtual_template", "")
        vt_id = pppoe.get("virtual_template_id", "")
        iface_name = iface.get("name", "")

        # Check virtual-template reference
        if vt_ref and vt_ref not in vt_names:
            missing_references.append({
                "type": "pppoe_virtual_template_not_found",
                "name": vt_ref,
                "referenced_by": iface_name,
            })

        # Check BAS domain
        bas = iface.get("bas", {})
        domain = bas.get("default_domain") if bas else None

        # Collect PPP auth modes from referenced VT
        ppp_modes = []
        pool = None
        for vt in vts:
            if vt["name"] == vt_ref:
                ppp_modes = vt.get("ppp_authentication_modes", [])
                pool = vt.get("remote_address_pool")
                break

        pppoe_interfaces.append({
            "interface": iface_name,
            "description": iface.get("description", ""),
            "user_vlan": iface.get("user_vlan"),
            "qinq_vlan": iface.get("qinq_vlan"),
            "virtual_template": vt_ref,
            "virtual_template_id": vt_id,
            "max_sessions": pppoe.get("max_sessions"),
            "domain": domain,
            "authentication_method": bas.get("authentication_method") if bas else None,
            "ppp_authentication_modes": ppp_modes,
            "ip_pool": pool,
        })

    # Check for orphan Virtual-Templates (defined but not used)
    used_vts = set()
    for iface in interfaces:
        pppoe = iface.get("pppoe_server")
        if pppoe and pppoe.get("enabled"):
            used_vts.add(pppoe.get("virtual_template"))
    for vt in vts:
        if vt["name"] not in used_vts:
            missing_references.append({
                "type": "virtual_template_orphan",
                "name": vt["name"],
                "referenced_by": "(nenhuma interface PPPoE)",
            })

    return {
        "pppoe_interfaces": pppoe_interfaces,
        "virtual_templates": vts,
        "missing_references": missing_references,
    }
