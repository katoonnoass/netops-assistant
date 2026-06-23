from django.db.models import Count, Q

from .models import (
    DeviceLink,
    TopologyEvidence,
    VlanDefinition,
    VlanEndpoint,
    VlanInterface,
    VlanPath,
    VlanTrackDevice,
    VlanTrackSession,
    VlanTrackingIssue,
)
from .troubleshooter import build_vlan_troubleshooting_report, classify_vlan_health


def get_vlan_tracking_dashboard_summary():
    sessions = VlanTrackSession.objects.all().order_by("-created_at")
    total_sessions = sessions.count()
    total_vlans = VlanDefinition.objects.count()
    total_issues = VlanTrackingIssue.objects.count()
    low_conf_links = DeviceLink.objects.filter(confidence="low").count()
    last_session = sessions.first()

    top_vlans_with_issues = list(
        VlanTrackingIssue.objects.exclude(vlan_definition=None)
        .values("vlan_definition__vlan_id", "vlan_definition__session__name",
                "vlan_definition__session_id")
        .annotate(total=Count("id"))
        .order_by("-total")[:10]
    )

    low_conf_list = list(
        DeviceLink.objects.filter(confidence="low")
        .select_related("session", "device_a", "device_b")[:10]
    )

    return {
        "total_sessions": total_sessions,
        "total_vlans": total_vlans,
        "total_issues": total_issues,
        "low_conf_links_count": low_conf_links,
        "last_session": last_session,
        "top_vlans_with_issues": top_vlans_with_issues,
        "low_conf_list": low_conf_list,
    }


def search_vlan_tracking(query):
    results = []
    q = query.strip().lower()
    if not q:
        return results

    # Search sessions
    for s in VlanTrackSession.objects.filter(
        Q(name__icontains=q) | Q(description__icontains=q)
    )[:10]:
        results.append({
            "type": "vlan_tracking_session",
            "title": f"Sessão: {s.name}",
            "description": s.description or "",
            "url": f"/vlan/{s.pk}/",
            "score": 0.9,
        })

    # Search VLAN definitions
    vlan_filter = Q(name__icontains=q)
    if q.isdigit():
        vlan_filter = vlan_filter | Q(vlan_id__icontains=q)
    for v in VlanDefinition.objects.filter(vlan_filter).select_related("session")[:20]:
        health = classify_vlan_health(v.session, v.vlan_id)
        results.append({
            "type": "tracked_vlan",
            "title": f"VLAN {v.vlan_id} — {v.session.name}",
            "description": f"{health['label']} — {v.name or '-'}",
            "url": f"/vlan/{v.session.pk}/troubleshoot/{v.vlan_id}/",
            "score": 0.85,
        })

    # Search issues
    for issue in VlanTrackingIssue.objects.filter(
        Q(code__icontains=q) | Q(title__icontains=q) | Q(description__icontains=q)
    ).select_related("session", "vlan_definition")[:20]:
        vlan_part = f"VLAN {issue.vlan_definition.vlan_id}" if issue.vlan_definition else ""
        results.append({
            "type": "vlan_tracking_issue",
            "title": f"[{issue.severity}] {issue.code}: {issue.title}",
            "description": f"{issue.session.name} {vlan_part}",
            "url": f"/vlan/{issue.session.pk}/troubleshoot/{issue.vlan_definition.vlan_id}/" if issue.vlan_definition else f"/vlan/{issue.session.pk}/",
            "score": 0.8,
        })

    # Search links
    for link in DeviceLink.objects.filter(
        Q(interface_a__icontains=q) | Q(interface_b__icontains=q) |
        Q(device_a__name__icontains=q) | Q(device_b__name__icontains=q) |
        Q(discovery_method__icontains=q) | Q(confidence__icontains=q)
    ).select_related("session", "device_a", "device_b")[:20]:
        results.append({
            "type": "vlan_tracking_link",
            "title": f"{link.device_a.name}:{link.interface_a} ↔ {link.device_b.name}:{link.interface_b}",
            "description": f"{link.get_discovery_method_display()}/{link.get_confidence_display()} — {link.session.name}",
            "url": f"/vlan/{link.session.pk}/topology/",
            "score": 0.75,
        })

    # Search endpoints
    for ep in VlanEndpoint.objects.filter(
        Q(interface_name__icontains=q) | Q(device__name__icontains=q)
    ).select_related("session", "device", "vlan_definition")[:20]:
        results.append({
            "type": "vlan_tracking_endpoint",
            "title": f"{ep.get_endpoint_type_display()}: {ep.device.name}:{ep.interface_name}",
            "description": f"VLAN {ep.vlan_definition.vlan_id} — {ep.session.name}",
            "url": f"/vlan/{ep.session.pk}/vlan/{ep.vlan_definition.vlan_id}/",
            "score": 0.7,
        })

    return sorted(results, key=lambda x: x["score"], reverse=True)[:50]


def get_device_vlan_tracking_context(device):
    sessions = VlanTrackSession.objects.filter(track_devices__device=device).distinct()
    context_list = []
    for s in sessions:
        vlan_ids = list(
            VlanInterface.objects.filter(session=s, device=device)
            .values_list("vlan_id", flat=True).distinct()[:20]
        )
        link_count = DeviceLink.objects.filter(
            session=s, device_a=device
        ).count() + DeviceLink.objects.filter(
            session=s, device_b=device
        ).count()
        issue_count = VlanTrackingIssue.objects.filter(
            session=s, device=device
        ).count()
        context_list.append({
            "session": s,
            "vlan_ids": vlan_ids,
            "link_count": link_count,
            "issue_count": issue_count,
        })
    return context_list


def export_session_report_text(session):
    lines = []
    lines.append(f"Relatório Consolidado — Sessão {session.name}")
    lines.append("=" * 60)
    devices = session.track_devices.select_related("device")
    links = DeviceLink.objects.filter(session=session)
    vlans = VlanDefinition.objects.filter(session=session)
    issues = VlanTrackingIssue.objects.filter(session=session)
    endpoints = VlanEndpoint.objects.filter(session=session)

    lines.append(f"\nDispositivos ({devices.count()}):")
    for td in devices:
        lines.append(f"  - {td.device.name} ({td.get_role_hint_display()})")

    lines.append(f"\nLinks ({links.count()}):")
    for link in links:
        lines.append(f"  {link.device_a}:{link.interface_a} ↔ {link.device_b}:{link.interface_b} ({link.get_discovery_method_display()}/{link.get_confidence_display()})")

    lines.append(f"\nVLANs ({vlans.count()}):")
    for v in vlans.order_by("vlan_id")[:50]:
        lines.append(f"  VLAN {v.vlan_id} - {v.name or '-'} ({v.device_count} devices, {v.interface_count} ifaces)")

    lines.append(f"\nEndpoints ({endpoints.count()}):")
    for ep in endpoints.select_related("device", "vlan_definition")[:30]:
        lines.append(f"  VLAN {ep.vlan_definition.vlan_id}: {ep.device.name}:{ep.interface_name} ({ep.get_endpoint_type_display()})")

    lines.append(f"\nIssues ({issues.count()}):")
    for issue in issues[:30]:
        lines.append(f"  [{issue.severity}] {issue.code}: {issue.title}")

    lines.append(f"\nLinks de Baixa Confiança ({links.filter(confidence='low').count()}):")
    for link in links.filter(confidence="low"):
        lines.append(f"  {link.device_a}:{link.interface_a} ↔ {link.device_b}:{link.interface_b} ({link.get_discovery_method_display()})")

    return "\n".join(lines)


def export_session_report_csv_rows(session):
    import csv
    import io
    from django.urls import reverse

    rows = []
    devices = session.track_devices.select_related("device")
    links = DeviceLink.objects.filter(session=session)
    vlans = VlanDefinition.objects.filter(session=session)
    issues = VlanTrackingIssue.objects.filter(session=session)
    endpoints = VlanEndpoint.objects.filter(session=session)

    for td in devices:
        rows.append({"section": "device", "session": session.name, "vlan_id": "", "device": td.device.name, "interface": "", "type": "device", "status": "", "severity": "", "description": f"Role: {td.get_role_hint_display()}", "url": ""})

    for link in links:
        rows.append({"section": "link", "session": session.name, "vlan_id": "", "device": f"{link.device_a} ↔ {link.device_b}", "interface": f"{link.interface_a} ↔ {link.interface_b}", "type": link.discovery_method, "status": link.status, "severity": link.confidence, "description": "", "url": ""})

    for v in vlans:
        rows.append({"section": "vlan", "session": session.name, "vlan_id": str(v.vlan_id), "device": "", "interface": "", "type": "vlan", "status": "", "severity": "", "description": f"{v.name or '-'} ({v.device_count} devices)", "url": reverse("vlan_tracking:troubleshoot_detail", args=[session.pk, v.vlan_id])})

    for ep in endpoints.select_related("device", "vlan_definition"):
        rows.append({"section": "endpoint", "session": session.name, "vlan_id": str(ep.vlan_definition.vlan_id), "device": ep.device.name, "interface": ep.interface_name, "type": ep.endpoint_type, "status": "", "severity": "", "description": ep.get_endpoint_type_display(), "url": ""})

    for issue in issues:
        rows.append({"section": "issue", "session": session.name, "vlan_id": str(issue.vlan_definition.vlan_id) if issue.vlan_definition else "", "device": issue.device.name if issue.device else "", "interface": issue.interface_name, "type": issue.code, "status": "", "severity": issue.severity, "description": issue.title, "url": ""})

    return rows
