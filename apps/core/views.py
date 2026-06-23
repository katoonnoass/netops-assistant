"""Views do app Core — dashboard, auditoria, backup."""

from django.shortcuts import render

from apps.analysis.models import (
    AnalysisIssue,
    ConfigComparison,
    DetectedCircuit,
    DetectedService,
)
from apps.analysis.operational import (
    get_latest_parsed_configs_by_device,
    get_operational_summary,
    get_recommended_actions,
)
from apps.config_archive.models import ConfigSnapshot
from apps.core.models import AuditLog
from apps.core.permissions import admin_required, viewer_required
from apps.devices.models import Device
from apps.devices.operational import (
    get_device_status,
    get_devices_without_snapshot_count,
    get_snapshots_last_7_days,
    get_top_issues_devices,
    get_vendor_summary,
)


@viewer_required
def dashboard(request):
    """Página inicial com resumo operacional consolidado."""
    summary = get_operational_summary()
    latest = get_latest_parsed_configs_by_device()
    actions = get_recommended_actions()
    recent_comparisons = ConfigComparison.objects.select_related(
        "base_snapshot__device", "target_snapshot__device"
    ).all()[:5]
    recent_snapshots = ConfigSnapshot.objects.select_related("device").all()[:5]

    # Devices in attention
    devices_in_attention = []
    for device in Device.objects.all():
        status = get_device_status(device)
        if status in ("critical", "warning"):
            devices_in_attention.append({
                "pk": device.pk,
                "name": device.name,
                "attention_type": status,
                "attention_label": "Crítico" if status == "critical" else "Atenção",
            })
    devices_in_attention.sort(
        key=lambda d: 0 if d["attention_type"] == "critical" else 1
    )

    context = {
        "summary": summary,
        "latest_parsed": latest,
        "actions": actions,
        "recent_comparisons": recent_comparisons,
        "recent_snapshots": recent_snapshots,
        "devices_in_attention": devices_in_attention,
        "vendor_summary": get_vendor_summary(),
        "top_issues_devices": get_top_issues_devices(5),
        "snapshots_7d": get_snapshots_last_7_days(),
        "devices_without_snapshot": get_devices_without_snapshot_count(),
        "vendors_count": len(get_vendor_summary()),
    }
    return render(request, "core/dashboard.html", context)


@admin_required
def audit_list(request):
    """Lista de logs de auditoria — somente Admin."""
    actions = AuditLog.objects.values_list("action", flat=True).distinct().order_by("action")
    selected_action = request.GET.get("action", "")
    selected_user = request.GET.get("user", "")

    qs = AuditLog.objects.select_related("user").all()
    if selected_action:
        qs = qs.filter(action=selected_action)
    if selected_user:
        qs = qs.filter(user__username__icontains=selected_user)

    logs = qs[:200]
    return render(request, "audit/audit_list.html", {
        "logs": logs,
        "actions": actions,
        "selected_action": selected_action,
        "selected_user": selected_user,
    })


@admin_required
def backup_page(request):
    """Página de exportação de backup — somente Admin."""
    return render(request, "admin_tools/backup.html")
