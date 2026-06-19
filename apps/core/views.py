"""Views do app Core — dashboard."""

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
from apps.devices.models import Device
from apps.devices.operational import get_device_status


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
    }
    return render(request, "core/dashboard.html", context)
