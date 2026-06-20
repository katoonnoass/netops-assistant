"""Utilitário para análise de QoS / Traffic Policy / CAR.

Fornece funções para construir sumário de QoS, mapa de dependências
e detecção de issues específicas de QoS.
"""

from __future__ import annotations


def build_qos_summary(parsed_data: dict) -> dict | None:
    """Build a summary of all QoS configuration in parsed data."""
    qos = parsed_data.get("qos", {})
    if not qos:
        return None

    classifiers = qos.get("traffic_classifiers", [])
    behaviors = qos.get("traffic_behaviors", [])
    policies = qos.get("traffic_policies", [])
    profiles = qos.get("qos_profiles", [])

    if not any([classifiers, behaviors, policies, profiles]):
        return None

    interfaces_with_qos = []
    for iface in parsed_data.get("interfaces", []):
        if iface.get("traffic_policies_applied") or iface.get("qos_profiles_applied") or iface.get("qos_car"):
            interfaces_with_qos.append(iface["name"])

    inbound_count = sum(
        1 for i in parsed_data.get("interfaces", [])
        for tp in i.get("traffic_policies_applied", [])
        if tp.get("direction") == "inbound"
    )
    outbound_count = sum(
        1 for i in parsed_data.get("interfaces", [])
        for tp in i.get("traffic_policies_applied", [])
        if tp.get("direction") == "outbound"
    )

    return {
        "total_classifiers": len(classifiers),
        "total_behaviors": len(behaviors),
        "total_policies": len(policies),
        "total_qos_profiles": len(profiles),
        "interfaces_with_qos": len(interfaces_with_qos),
        "interface_names": interfaces_with_qos,
        "inbound_policy_count": inbound_count,
        "outbound_policy_count": outbound_count,
        "car_rates_found": sum(
            1 for b in behaviors if b.get("car") is not None
        ),
    }


def build_qos_dependency_map(parsed_data: dict) -> dict:
    """Build a dependency map for QoS components.

    Relates:
    - traffic-policy → classifier → behavior → CAR/ACL
    - interface → traffic-policy/qos-profile
    - interface → VPN-instance

    Detects orphans: policies/classifiers/behaviors/profiles not referenced.
    """
    qos = parsed_data.get("qos", {})
    acls = parsed_data.get("acls", [])
    acl_names = {a.get("name", ""): a for a in acls}
    acl_numbers = {a.get("number", ""): a for a in acls}

    # Build lookup sets
    classifier_names = {c["name"] for c in qos.get("traffic_classifiers", [])}
    behavior_names = {b["name"] for b in qos.get("traffic_behaviors", [])}
    policy_names = {p["name"] for p in qos.get("traffic_policies", [])}
    profile_names = {p["name"] for p in qos.get("qos_profiles", [])}

    # Track which are referenced
    referenced_classifiers: set[str] = set()
    referenced_behaviors: set[str] = set()
    referenced_policies: set[str] = set()
    referenced_profiles: set[str] = set()
    referenced_acls: set[str] = set()

    policies_detail = []
    for policy in qos.get("traffic_policies", []):
        pname = policy["name"]
        bindings = []
        for iface in parsed_data.get("interfaces", []):
            for tp in iface.get("traffic_policies_applied", []):
                if tp["name"] == pname:
                    vpn = iface.get("vpn_instance")
                    bindings.append({
                        "interface": iface["name"],
                        "direction": tp["direction"],
                        "vpn_instance": vpn,
                    })

        classifiers_detail = []
        for ce in policy.get("classifiers", []):
            cname = ce["classifier"]
            bname = ce["behavior"]
            referenced_classifiers.add(cname)
            referenced_behaviors.add(bname)

            # Find ACL refs from classifier
            acl_refs = []
            car_info = None
            for cl in qos.get("traffic_classifiers", []):
                if cl["name"] == cname:
                    for im in cl.get("if_match", []):
                        if im["type"] == "acl":
                            acl_refs.append(im["value"])
                            referenced_acls.add(im["value"])
                    break

            # Find CAR from behavior
            for bh in qos.get("traffic_behaviors", []):
                if bh["name"] == bname and bh.get("car"):
                    car_info = {
                        "cir": bh["car"].get("cir"),
                        "pir": bh["car"].get("pir"),
                    }
                    break

            classifiers_detail.append({
                "name": cname,
                "behavior": bname,
                "acl_refs": acl_refs,
                "car": car_info,
            })

        policies_detail.append({
            "name": pname,
            "bindings": bindings,
            "classifiers": classifiers_detail,
        })

    # Track referenced policies from interfaces
    for iface in parsed_data.get("interfaces", []):
        for tp in iface.get("traffic_policies_applied", []):
            referenced_policies.add(tp["name"])
        for qp in iface.get("qos_profiles_applied", []):
            referenced_profiles.add(qp["name"])

    # Find orphans
    orphan_policies = sorted(policy_names - referenced_policies)
    orphan_classifiers = sorted(classifier_names - referenced_classifiers)
    orphan_behaviors = sorted(behavior_names - referenced_behaviors)
    orphan_qos_profiles = sorted(profile_names - referenced_profiles)

    return {
        "policies": policies_detail,
        "orphan_policies": orphan_policies,
        "orphan_classifiers": orphan_classifiers,
        "orphan_behaviors": orphan_behaviors,
        "orphan_qos_profiles": orphan_qos_profiles,
    }
