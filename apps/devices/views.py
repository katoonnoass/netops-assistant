"""Views de dispositivo — listagem, detalhe, export CSV."""

import csv

from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render

from apps.devices.models import Device
from apps.devices.operational import (
    filter_devices,
    get_device_recommended_actions,
    get_device_summary,
    get_device_timeline,
)


def device_list(request):
    vendor = request.GET.get("vendor", "")
    status = request.GET.get("status", "")
    q = request.GET.get("q", "")
    devices = filter_devices(vendor=vendor, status=status, q=q)
    vendor_choices = Device.Vendor.choices
    return render(request, "devices/device_list.html", {
        "devices": devices,
        "vendor_choices": vendor_choices,
        "filter_vendor": vendor,
        "filter_status": status,
        "filter_q": q,
    })


def device_detail(request, pk):
    device = get_object_or_404(Device, pk=pk)
    summary = get_device_summary(device)
    timeline = get_device_timeline(device)
    actions = get_device_recommended_actions(device)
    return render(request, "devices/device_detail.html", {
        "summary": summary,
        "timeline": timeline,
        "actions": actions,
    })


def device_export(request):
    vendor = request.GET.get("vendor", "")
    status = request.GET.get("status", "")
    q = request.GET.get("q", "")
    devices = filter_devices(vendor=vendor, status=status, q=q)
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="devices.csv"'
    w = csv.writer(response)
    w.writerow([
        "id", "name", "hostname", "vendor", "ip", "total_snapshots",
        "last_snapshot_date", "operational_status",
        "circuits_count_latest", "services_count_latest",
        "high_issues_latest", "medium_issues_latest", "low_issues_latest",
    ])
    for d in devices:
        from apps.analysis.models import AnalysisIssue
        from apps.config_archive.models import ConfigSnapshot
        last_snap = ConfigSnapshot.objects.filter(device=d["device"]).order_by("-created_at").first()
        high = medium = low = 0
        if last_snap:
            issues = AnalysisIssue.objects.filter(snapshot=last_snap)
            high = issues.filter(severity="critical").count()
            medium = issues.filter(severity="warning").count()
            low = issues.filter(severity="info").count()
        w.writerow([
            d["device"].pk, d["device"].name, d["device"].hostname,
            d["device"].vendor, d["device"].ip_address or "",
            d["total_snapshots"],
            d["last_snapshot_date"].isoformat() if d["last_snapshot_date"] else "",
            d["status"],
            d["circuits_count"], d["services_count"],
            high, medium, low,
        ])
    return response
