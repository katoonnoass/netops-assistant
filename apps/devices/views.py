"""Views de dispositivo — listagem, detalhe, upload, comparação."""

import csv
import os

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from apps.analysis.services import analyze_config_snapshot
from apps.analysis.models import ConfigComparison
from apps.config_archive.models import ConfigSnapshot
from apps.core.audit import record_audit_event
from apps.core.permissions import operator_required, viewer_required
from apps.devices.models import Device
from apps.devices.operational import (
    filter_devices,
    get_device_recommended_actions,
    get_device_status,
    get_device_summary,
    get_device_timeline,
    get_snapshots_for_device,
)


# ── Helpers de upload ─────────────────────────────────────────────────


ALLOWED_UPLOAD_EXTENSIONS = {".txt", ".cfg", ".conf"}
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB


def _validate_uploaded_file(uploaded_file) -> str | None:
    """Valida extensão, tamanho e conteúdo do arquivo. Retorna erro ou None."""
    if uploaded_file.size > MAX_UPLOAD_SIZE:
        return f"Arquivo muito grande. Máximo permitido: {MAX_UPLOAD_SIZE // (1024*1024)} MB."

    ext = os.path.splitext(uploaded_file.name)[1].lower()
    if ext and ext not in ALLOWED_UPLOAD_EXTENSIONS:
        allowed = ", ".join(sorted(ALLOWED_UPLOAD_EXTENSIONS))
        return f"Extensão não permitida: '{ext}'. Permitidas: {allowed}"

    try:
        raw = uploaded_file.read().decode("utf-8", errors="strict")
    except (UnicodeDecodeError, UnicodeError):
        return "Arquivo binário ou codificação não suportada. Apenas arquivos de texto (UTF-8) são aceitos."

    return None


# ── Views ─────────────────────────────────────────────────────────────


@viewer_required
def device_list(request):
    vendor = request.GET.get("vendor", "")
    status = request.GET.get("status", "")
    q = request.GET.get("q", "")
    role = request.GET.get("role", "")
    site = request.GET.get("site", "")
    platform = request.GET.get("platform", "")
    devices = filter_devices(vendor=vendor, status=status, q=q, role=role, site=site, platform=platform)
    vendor_choices = Device.Vendor.choices
    role_choices = Device.Role.choices
    return render(request, "devices/device_list.html", {
        "devices": devices,
        "vendor_choices": vendor_choices,
        "role_choices": role_choices,
        "filter_vendor": vendor,
        "filter_status": status,
        "filter_q": q,
        "filter_role": role,
        "filter_site": site,
        "filter_platform": platform,
    })


@viewer_required
def device_detail(request, pk):
    device = get_object_or_404(Device, pk=pk)
    summary = get_device_summary(device)
    timeline = get_device_timeline(device)
    actions = get_device_recommended_actions(device)

    # VLAN Tracking context
    try:
        from apps.vlan_tracking.operational import get_device_vlan_tracking_context
        vlan_context = get_device_vlan_tracking_context(device)
    except Exception:
        vlan_context = []

    return render(request, "devices/device_detail.html", {
        "summary": summary,
        "timeline": timeline,
        "actions": actions,
        "vlan_context": vlan_context,
    })


@viewer_required
def device_snapshot_list(request, pk):
    device = get_object_or_404(Device, pk=pk)
    snapshots = get_snapshots_for_device(device)
    return render(request, "devices/snapshot_list.html", {
        "device": device,
        "snapshots": snapshots,
        "status": get_device_status(device),
    })


@operator_required
def device_snapshot_upload(request, pk):
    device = get_object_or_404(Device, pk=pk)

    if request.method == "POST":
        raw_config = request.POST.get("raw_config", "")
        file_config = ""
        upload_error = None

        if request.FILES.get("config_file"):
            uploaded = request.FILES["config_file"]
            upload_error = _validate_uploaded_file(uploaded)
            if upload_error:
                messages.error(request, upload_error)
                return render(request, "devices/snapshot_upload.html", {"device": device})
            uploaded.seek(0)
            file_config = uploaded.read().decode("utf-8", errors="replace")

        config_text = file_config or raw_config
        if not config_text.strip():
            messages.error(request, "A configuração não pode estar vazia.")
            return render(request, "devices/snapshot_upload.html", {"device": device})

        source = "upload" if file_config else "paste"
        name = request.POST.get("name", "")
        notes = request.POST.get("notes", "")
        description = request.POST.get("description", "")
        is_baseline = request.POST.get("is_baseline") == "on"
        captured_at_str = request.POST.get("captured_at", "")

        captured_at = None
        if captured_at_str:
            from datetime import datetime
            try:
                captured_at = datetime.strptime(captured_at_str, "%Y-%m-%dT%H:%M")
                if timezone.is_naive(captured_at):
                    captured_at = timezone.make_aware(captured_at)
            except ValueError:
                pass

        snapshot = ConfigSnapshot(
            device=device,
            name=name,
            raw_config=config_text,
            vendor=device.vendor,
            source=source,
            notes=notes,
            description=description,
            is_baseline=is_baseline,
            captured_at=captured_at,
        )
        # Check duplicate before saving
        dup = snapshot.is_duplicate_of()
        if dup:
            record_audit_event(
                user=request.user,
                action="snapshot_duplicate_blocked",
                object_type="ConfigSnapshot",
                object_id=f"dup_of_{dup.pk}",
                description=f"Snapshot duplicado bloqueado para {device.name} — hash {snapshot.hash_short or snapshot.config_hash[:12]} já existe em #{dup.pk}",
                request=request,
            )
            dt_str = dup.created_at.strftime("%d/%m/%Y %H:%M")
            messages.warning(
                request,
                f"Esta configuração já foi enviada em {dt_str} (#{dup.pk}). "
                "O snapshot duplicado não foi criado.",
            )
            return redirect("device_snapshot_list", pk=device.pk)

        snapshot.save()
        record_audit_event(
            user=request.user,
            action="snapshot_uploaded",
            object_type="ConfigSnapshot",
            object_id=snapshot.pk,
            description=f"Snapshot #{snapshot.pk} enviado para {device.name}",
            request=request,
        )
        parsed = analyze_config_snapshot(snapshot)
        messages.success(request, f"Snapshot #{snapshot.pk} criado e analisado com sucesso.")
        return redirect("analysis_detail", pk=parsed.pk)

    return render(request, "devices/snapshot_upload.html", {"device": device})


@operator_required
def device_compare(request, pk):
    device = get_object_or_404(Device, pk=pk)
    snapshots = ConfigSnapshot.objects.filter(device=device).order_by("-created_at", "-pk")

    if request.method == "POST":
        base_id = request.POST.get("base_snapshot")
        target_id = request.POST.get("target_snapshot")

        if not base_id or not target_id:
            messages.error(request, "Selecione dois snapshots para comparar.")
            return render(request, "devices/device_compare.html", {"device": device, "snapshots": snapshots})

        if base_id == target_id:
            messages.error(request, "Selecione dois snapshots diferentes.")
            return render(request, "devices/device_compare.html", {"device": device, "snapshots": snapshots})

        base = get_object_or_404(ConfigSnapshot, pk=base_id, device=device)
        target = get_object_or_404(ConfigSnapshot, pk=target_id, device=device)

        # Check if comparison already exists
        existing = ConfigComparison.objects.filter(
            base_snapshot=base, target_snapshot=target
        ).first()
        if existing:
            return redirect("comparison_detail", pk=existing.pk)

        comp = ConfigComparison.objects.create(
            base_snapshot=base,
            target_snapshot=target,
            title=f"{device.name} - #{base.pk} vs #{target.pk}",
        )
        record_audit_event(
            user=request.user,
            action="comparison_created",
            object_type="ConfigComparison",
            object_id=comp.pk,
            description=f"Comparação #{comp.pk}: {device.name} #{base.pk} vs #{target.pk}",
            request=request,
        )
        messages.success(request, "Comparação criada com sucesso.")
        return redirect("comparison_detail", pk=comp.pk)

    return render(request, "devices/device_compare.html", {"device": device, "snapshots": snapshots})


@viewer_required
def device_export(request):
    vendor = request.GET.get("vendor", "")
    status = request.GET.get("status", "")
    q = request.GET.get("q", "")
    role = request.GET.get("role", "")
    site = request.GET.get("site", "")
    platform = request.GET.get("platform", "")
    devices = filter_devices(vendor=vendor, status=status, q=q, role=role, site=site, platform=platform)
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="devices.csv"'
    w = csv.writer(response)
    w.writerow([
        "id", "name", "hostname", "vendor", "platform", "role", "site", "ip", "total_snapshots",
        "last_snapshot_date", "operational_status",
        "circuits_count_latest", "services_count_latest",
        "high_issues_latest", "medium_issues_latest", "low_issues_latest",
    ])
    for d in devices:
        from apps.analysis.models import AnalysisIssue
        last_snap = d["last_snapshot"]
        high = medium = low = 0
        if last_snap:
            issues = AnalysisIssue.objects.filter(snapshot=last_snap)
            high = issues.filter(severity="critical").count()
            medium = issues.filter(severity="warning").count()
            low = issues.filter(severity="info").count()
        w.writerow([
            d["device"].pk, d["device"].name, d["device"].hostname,
            d["device"].vendor, d["device"].platform, d["device"].role, d["device"].site,
            d["device"].ip_address or "",
            d["total_snapshots"],
            d["last_snapshot_date"].isoformat() if d["last_snapshot_date"] else "",
            d["status"],
            d["circuits_count"], d["services_count"],
            high, medium, low,
        ])
    return response
