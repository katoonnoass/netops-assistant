"""Views para o app analysis — resultado e documentação da análise."""

from django.shortcuts import get_object_or_404, render

from apps.analysis.documentation import generate_analysis_documentation
from apps.analysis.models import ParsedConfig


def analysis_detail(request, pk):
    """Exibe o resultado completo de uma análise."""
    parsed = get_object_or_404(
        ParsedConfig.objects.select_related("snapshot__device"), pk=pk
    )
    snapshot = parsed.snapshot

    circuits = snapshot.detected_circuits.all()
    issues = snapshot.analysis_issues.all()
    services = snapshot.detected_services.all()

    interfaces = parsed.parsed_data.get("interfaces", [])
    routes = parsed.parsed_data.get("static_routes", [])

    context = {
        "parsed": parsed,
        "snapshot": snapshot,
        "circuits": circuits,
        "issues": issues,
        "services": services,
        "interfaces_count": len(interfaces),
        "routes_count": len(routes),
    }
    return render(request, "analysis/detail.html", context)


def analysis_documentation(request, pk):
    """Exibe a documentação automática gerada a partir da análise."""
    parsed = get_object_or_404(
        ParsedConfig.objects.select_related("snapshot__device"), pk=pk
    )
    doc = generate_analysis_documentation(parsed)

    context = {
        "parsed": parsed,
        "doc": doc,
    }
    return render(request, "analysis/documentation.html", context)
