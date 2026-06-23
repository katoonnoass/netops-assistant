from .models import (
    DeviceLink,
    TopologyEvidence,
    VlanDefinition,
    VlanPath,
    VlanTrackingIssue,
)

CONFIDENCE_LABELS = {
    "high": "Alta",
    "medium": "Média",
    "low": "Baixa",
}
METHOD_LABELS = {
    "manual": "Manual",
    "lldp": "LLDP",
    "csv": "CSV",
    "subnet": "Sub-rede",
    "description": "Descrição",
}
METHOD_ORDER = ["manual", "csv", "lldp", "description", "subnet"]


def format_confidence_label(confidence):
    return CONFIDENCE_LABELS.get(confidence, confidence)


def format_discovery_method_label(method):
    return METHOD_LABELS.get(method, method)


def get_link_vlans(link):
    return list(
        VlanPath.objects.filter(
            session=link.session, via_link=link
        ).select_related("vlan_definition").distinct()
    )


def get_link_vlan_ids(link):
    return sorted(set(
        VlanPath.objects.filter(
            session=link.session, via_link=link
        ).values_list("vlan_definition__vlan_id", flat=True)
    ))


def get_link_issues(link):
    return list(
        VlanTrackingIssue.objects.filter(
            session=link.session,
            device__in=[link.device_a_id, link.device_b_id],
        ).filter(
            code__in=[
                "vlan_path_uses_low_confidence_link",
                "vlan_on_trunk_missing_on_neighbor",
            ]
        )[:10]
    )


def get_link_display_data(session, filters=None):
    qs = DeviceLink.objects.filter(session=session).select_related(
        "device_a", "device_b", "evidence"
    ).order_by("discovery_method", "-confidence")

    if filters:
        if filters.get("method"):
            qs = qs.filter(discovery_method=filters["method"])
        if filters.get("confidence"):
            qs = qs.filter(confidence=filters["confidence"])
        if filters.get("device"):
            qs = qs.filter(
                device_a__name__icontains=filters["device"]
            ) | qs.filter(
                device_b__name__icontains=filters["device"]
            )
        if filters.get("vlan"):
            vlan_id = int(filters["vlan"])
            link_ids = VlanPath.objects.filter(
                session=session, vlan_definition__vlan_id=vlan_id
            ).values_list("via_link_id", flat=True)
            qs = qs.filter(id__in=link_ids)
        if filters.get("status"):
            qs = qs.filter(status=filters["status"])

    result = []
    for link in qs:
        vlan_ids = get_link_vlan_ids(link)
        issues = get_link_issues(link)
        result.append({
            "link": link,
            "device_a_id": link.device_a_id,
            "device_b_id": link.device_b_id,
            "device_a_name": link.device_a.name,
            "device_b_name": link.device_b.name,
            "interface_a": link.interface_a,
            "interface_b": link.interface_b,
            "method": link.discovery_method,
            "method_label": format_discovery_method_label(link.discovery_method),
            "confidence": link.confidence,
            "confidence_label": format_confidence_label(link.confidence),
            "status": link.status,
            "vlan_ids": vlan_ids[:10],
            "vlan_count": len(vlan_ids),
            "issues": issues,
            "issue_count": len(issues),
            "has_evidence": bool(link.evidence_id),
            "evidence_type": link.evidence.evidence_type if link.evidence else None,
        })
    return result


def get_vlan_path_display_data(session, vlan_id):
    from .models import VlanDefinition, VlanEndpoint, VlanInterface, VlanPath, VlanTrackingIssue

    vdef = VlanDefinition.objects.filter(session=session, vlan_id=vlan_id).first()
    if not vdef:
        return None

    paths = VlanPath.objects.filter(session=session, vlan_definition=vdef).select_related(
        "from_device", "to_device", "via_link"
    )
    interfaces = VlanInterface.objects.filter(session=session, vlan_id=vlan_id).select_related("device")
    endpoints = VlanEndpoint.objects.filter(session=session, vlan_definition=vdef).select_related("device")
    issues = VlanTrackingIssue.objects.filter(session=session, vlan_definition=vdef)

    path_segments = []
    has_low_confidence = False
    for p in paths:
        info = {
            "from_device": p.from_device.name,
            "from_interface": p.from_interface,
            "to_device": p.to_device.name,
            "to_interface": p.to_interface,
            "tagged": p.tagged,
            "method": p.via_link.discovery_method if p.via_link else "",
            "method_label": format_discovery_method_label(p.via_link.discovery_method) if p.via_link else "",
            "confidence": p.via_link.confidence if p.via_link else "",
            "confidence_label": format_confidence_label(p.via_link.confidence) if p.via_link else "",
            "low_confidence": p.via_link and p.via_link.confidence == "low",
        }
        if info["low_confidence"]:
            has_low_confidence = True
        path_segments.append(info)

    endpoint_data = []
    for ep in endpoints:
        endpoint_data.append({
            "device_name": ep.device.name,
            "interface_name": ep.interface_name,
            "type": ep.endpoint_type,
            "type_label": ep.get_endpoint_type_display(),
            "description": ep.description,
        })

    # Organize endpoints by type
    endpoints_by_type = {}
    for ep in endpoint_data:
        endpoints_by_type.setdefault(ep["type"], []).append(ep)

    return {
        "definition": vdef,
        "interfaces": interfaces,
        "paths": path_segments,
        "endpoints": endpoint_data,
        "endpoints_by_type": endpoints_by_type,
        "issues": issues,
        "has_low_confidence_path": has_low_confidence,
        "device_count": interfaces.values("device").distinct().count(),
        "interface_count": interfaces.count(),
        "path_count": len(path_segments),
        "issue_count": issues.count(),
    }


def _get_totals(session):
    links_qs = DeviceLink.objects.filter(session=session)
    return {
        "total_devices": session.track_devices.count(),
        "total_links": links_qs.count(),
        "links_manual": links_qs.filter(discovery_method="manual").count(),
        "links_csv": links_qs.filter(discovery_method="csv").count(),
        "links_lldp": links_qs.filter(discovery_method="lldp").count(),
        "links_subnet": links_qs.filter(discovery_method="subnet").count(),
        "links_description": links_qs.filter(discovery_method="description").count(),
        "links_low_confidence": links_qs.filter(confidence="low").count(),
        "vlans_with_path": VlanPath.objects.filter(session=session).values("vlan_definition").distinct().count(),
        "total_issues": VlanTrackingIssue.objects.filter(session=session).count(),
    }


def _sanitize_mermaid_name(name):
    return name.replace("-", "_").replace(" ", "_").replace(".", "_")


def _build_mermaid(session, vlan_filter=None):
    mermaid_lines = [f"%% VLAN Tracking: {session.name}", "graph LR"]
    links = DeviceLink.objects.filter(session=session).select_related("device_a", "device_b")

    for l in links:
        vlan_ids = list(VlanPath.objects.filter(
            session=session, via_link=l
        ).values_list("vlan_definition__vlan_id", flat=True).distinct()[:10])

        if vlan_filter and vlan_filter.isdigit():
            if int(vlan_filter) not in vlan_ids:
                continue

        label = f"{l.interface_a} ↔ {l.interface_b}<br/>{l.get_discovery_method_display()}/{l.get_confidence_display()}"
        if vlan_ids:
            label += f"<br/>VLANs: {','.join(str(v) for v in vlan_ids[:6])}"

        safe_a = _sanitize_mermaid_name(l.device_a.name)
        safe_b = _sanitize_mermaid_name(l.device_b.name)
        mermaid_lines.append(
            f'  {safe_a}["{l.device_a.name}"] -- "{label}" --> {safe_b}["{l.device_b.name}"]'
        )
    return "\n".join(mermaid_lines)


def get_topology_filter_options(session):
    return {
        "methods": DeviceLink.objects.filter(session=session)
            .values_list("discovery_method", flat=True).distinct().order_by(),
        "confidences": ["high", "medium", "low"],
        "statuses": ["discovered", "confirmed", "ignored"],
        "devices": list(
            session.track_devices.select_related("device")
            .values_list("device__name", flat=True)
        ),
    }
