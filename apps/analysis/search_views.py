"""Views de busca técnica global."""

from django.shortcuts import render

from apps.analysis.search import global_network_search
from apps.core.permissions import viewer_required
from apps.devices.models import Device


@viewer_required
def search_view(request):
    """Página de busca técnica global."""
    q = request.GET.get("q", "").strip()
    vendor = request.GET.get("vendor", "")
    device_filter = request.GET.get("device", "")
    last_only = request.GET.get("last_snapshot_only") == "on"

    results = None
    if q:
        filters = {}
        if vendor:
            filters["vendor"] = vendor
        if device_filter:
            filters["device"] = device_filter
        if last_only:
            filters["last_snapshot_only"] = True

        results = global_network_search(q, filters=filters if filters else None)

    devices_qs = Device.objects.all()
    vendor_choices = [("", "Todos")] + list(Device.Vendor.choices)

    return render(request, "analysis/search.html", {
        "query": q,
        "results": results,
        "vendor_choices": vendor_choices,
        "filter_vendor": vendor,
        "filter_device": device_filter,
        "filter_last_only": last_only,
        "devices_qs": devices_qs,
    })
