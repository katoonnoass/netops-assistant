"""Views para o app config_archive — nova análise e listagem."""

from django.shortcuts import redirect, render

from apps.analysis.services import analyze_config_snapshot
from apps.config_archive.forms import NewAnalysisForm
from apps.config_archive.models import ConfigSnapshot
from apps.core.permissions import operator_required, viewer_required
from apps.devices.models import Device


@operator_required
def new_analysis(request):
    """Cria um novo snapshot e executa a análise."""
    if request.method == "POST":
        form = NewAnalysisForm(request.POST)
        if form.is_valid():
            device_name = form.cleaned_data["device_name"]
            vendor = form.cleaned_data["vendor"]
            raw_config = form.cleaned_data["raw_config"]
            notes = form.cleaned_data.get("notes", "")

            device, _ = Device.objects.get_or_create(
                name=device_name,
                defaults={"vendor": vendor, "hostname": device_name},
            )

            snapshot = ConfigSnapshot.objects.create(
                device=device,
                raw_config=raw_config,
                vendor=vendor,
                source="paste",
                notes=notes,
            )

            parsed = analyze_config_snapshot(snapshot)

            return redirect("analysis_detail", pk=parsed.pk)
    else:
        form = NewAnalysisForm()

    return render(request, "config_archive/config_form.html", {"form": form})


@viewer_required
def snapshot_list(request):
    """Lista todos os snapshots de configuração."""
    snapshots = (
        ConfigSnapshot.objects.select_related("device")
        .prefetch_related("detected_circuits", "analysis_issues", "parsed_configs")
        .all()
    )
    return render(request, "config_archive/config_list.html", {"snapshots": snapshots})
