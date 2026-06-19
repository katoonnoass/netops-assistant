"""Views de comparação de configurações."""

from django.shortcuts import get_object_or_404, redirect, render

from apps.analysis.comparison import compare_config_snapshots
from apps.analysis.models import ConfigComparison
from apps.config_archive.models import ConfigSnapshot


def comparison_list(request):
    comparisons = ConfigComparison.objects.select_related(
        "base_snapshot__device", "target_snapshot__device"
    ).all()
    return render(request, "analysis/comparison_list.html", {"comparisons": comparisons})


def comparison_new(request):
    snapshots = ConfigSnapshot.objects.select_related("device").all()

    if request.method == "POST":
        base_id = request.POST.get("base_snapshot")
        target_id = request.POST.get("target_snapshot")
        title = request.POST.get("title", "")

        if not base_id or not target_id:
            return render(request, "analysis/comparison_form.html", {
                "snapshots": snapshots,
                "error": "Selecione os dois snapshots.",
            })
        if base_id == target_id:
            return render(request, "analysis/comparison_form.html", {
                "snapshots": snapshots,
                "error": "Os snapshots base e alvo devem ser diferentes.",
            })

        base = get_object_or_404(ConfigSnapshot, pk=base_id)
        target = get_object_or_404(ConfigSnapshot, pk=target_id)

        comparison = compare_config_snapshots(base, target, title=title)
        return redirect("comparison_detail", pk=comparison.pk)

    return render(request, "analysis/comparison_form.html", {"snapshots": snapshots})


def comparison_detail(request, pk):
    comparison = get_object_or_404(
        ConfigComparison.objects.select_related(
            "base_snapshot__device", "target_snapshot__device"
        ),
        pk=pk,
    )
    return render(request, "analysis/comparison_detail.html", {"comparison": comparison})
