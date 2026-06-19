"""Serviço operacional — visão consolidada dos dados analisados."""

from django.db.models import Count, Max, Q

from apps.analysis.models import (
    AnalysisIssue,
    ConfigComparison,
    DetectedCircuit,
    DetectedService,
    ParsedConfig,
)
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device


def get_operational_summary() -> dict:
    """Retorna resumo operacional com contagens e estatísticas."""
    devices = Device.objects.count()
    snapshots = ConfigSnapshot.objects.count()
    configs = ParsedConfig.objects.count()
    circuits = DetectedCircuit.objects.count()
    services = DetectedService.objects.count()
    issues = AnalysisIssue.objects.count()
    comparisons = ConfigComparison.objects.count()

    # Issue severity breakdown
    critical_issues = AnalysisIssue.objects.filter(severity="critical").count()
    warning_issues = AnalysisIssue.objects.filter(severity="warning").count()
    info_issues = AnalysisIssue.objects.filter(severity="info").count()

    # Circuit type breakdown
    circuit_types = list(
        DetectedCircuit.objects.values("circuit_type")
        .annotate(total=Count("circuit_type"))
        .order_by("-total")
    )

    # Service type breakdown
    service_types = list(
        DetectedService.objects.values("service_type")
        .annotate(total=Count("service_type"))
        .order_by("-total")
    )

    return {
        "devices": devices,
        "snapshots": snapshots,
        "parsed_configs": configs,
        "circuits": circuits,
        "services": services,
        "issues": issues,
        "comparisons": comparisons,
        "critical_issues": critical_issues,
        "warning_issues": warning_issues,
        "info_issues": info_issues,
        "circuit_types": circuit_types,
        "service_types": service_types,
    }


def get_latest_parsed_configs_by_device() -> list[ParsedConfig]:
    """Retorna o último ParsedConfig analisado por Device.

    Usa created_at do ParsedConfig para determinar o mais recente.
    Fallback para pk se datas forem iguais.
    """
    from django.db.models import Max, OuterRef, Subquery

    latest_per_device = (
        ParsedConfig.objects
        .filter(snapshot__device=OuterRef("snapshot__device"))
        .order_by("-created_at", "-pk")
    )
    return list(
        ParsedConfig.objects.filter(
            pk=Subquery(latest_per_device.values("pk")[:1])
        ).select_related("snapshot__device").order_by("-created_at")
    )


def get_recommended_actions() -> list[dict]:
    """Gera lista de ações recomendadas com base nos dados atuais."""
    actions: list[dict] = []

    # High severity issues
    high_issues = AnalysisIssue.objects.filter(severity="critical").count()
    if high_issues > 0:
        actions.append({
            "action": f"Resolver {high_issues} issue(s) de alta severidade.",
            "reason": "Issues críticas podem representar riscos operacionais imediatos.",
            "priority": "high",
            "url": "/issues/?severity=critical",
        })

    # Interfaces without description
    no_desc_count = AnalysisIssue.objects.filter(
        code="interface_missing_description"
    ).count()
    if no_desc_count > 0:
        actions.append({
            "action": f"Padronizar descriptions de {no_desc_count} interface(s) física(s).",
            "reason": "Descriptions ausentes dificultam troubleshooting.",
            "priority": "medium",
            "url": "/issues/?code=interface_missing_description",
        })

    # Subinterfaces without description
    sub_no_desc = AnalysisIssue.objects.filter(
        code="subinterface_missing_description"
    ).count()
    if sub_no_desc > 0:
        actions.append({
            "action": f"Adicionar descriptions em {sub_no_desc} subinterface(s) dot1q.",
            "reason": "Subinterfaces sem descrição dificultam identificar circuitos.",
            "priority": "medium",
            "url": "/issues/?code=subinterface_missing_description",
        })

    # Static routes without description
    route_no_desc = AnalysisIssue.objects.filter(
        code="static_route_missing_description"
    ).count()
    if route_no_desc > 0:
        actions.append({
            "action": f"Documentar {route_no_desc} rota(s) estática(s) sem descrição.",
            "reason": "Rotas sem descrição dificultam auditoria.",
            "priority": "medium",
            "url": "/issues/?code=static_route_missing_description",
        })

    # Unreachable next-hops
    unreachable = AnalysisIssue.objects.filter(
        code="static_route_unreachable_next_hop"
    ).count()
    if unreachable > 0:
        actions.append({
            "action": f"Validar {unreachable} next-hop(s) inalcançável(is).",
            "reason": "Next-hops inalcançáveis podem causar queda de serviço.",
            "priority": "high",
            "url": "/issues/?code=static_route_unreachable_next_hop",
        })

    # BGP peers without description
    bgp_no_desc = AnalysisIssue.objects.filter(
        code="bgp_peer_missing_description"
    ).count()
    if bgp_no_desc > 0:
        actions.append({
            "action": f"Adicionar descrição em {bgp_no_desc} peer(s) BGP.",
            "reason": "Peers sem descrição dificultam identificar vizinhos.",
            "priority": "medium",
            "url": "/issues/?code=bgp_peer_missing_description",
        })

    # BNG/RADIUS services detected
    has_bng = DetectedService.objects.filter(service_type="bng").exists()
    has_radius = DetectedService.objects.filter(service_type="radius").exists()
    if has_bng or has_radius:
        actions.append({
            "action": "Validar periodicamente servidores RADIUS e falhas AAA.",
            "reason": "Serviços de autenticação são críticos para assinantes.",
            "priority": "medium",
            "url": "/services/?type=bng",
        })

    # L3 circuits
    l3_count = DetectedCircuit.objects.filter(circuit_type="l3_transit").count()
    if l3_count > 0:
        actions.append({
            "action": f"Manter documentação de {l3_count} circuito(s) L3.",
            "reason": "Prefixos roteados e next-hops devem ser documentados.",
            "priority": "low",
            "url": "/circuits/?type=l3_transit",
        })

    # Recent BGP changes
    recent_bgp_changes = ConfigComparison.objects.filter(
        diff_data__bgp__peers_added__0__exists=True
    ).count()
    if recent_bgp_changes > 0:
        actions.append({
            "action": f"Revisar validações de BGP de {recent_bgp_changes} comparação(ões) recente(s).",
            "reason": "Mudanças em peers BGP podem impactar a tabela de rotas global.",
            "priority": "medium",
            "url": "/comparisons/",
        })

    # No recent analysis
    if ParsedConfig.objects.count() == 0:
        actions.append({
            "action": "Criar a primeira análise de configuração.",
            "reason": "Nenhum dado analisado ainda.",
            "priority": "high",
            "url": "/configs/new/",
        })

    return actions


def filter_circuits(
    circuit_type: str = "",
    device: str = "",
    vendor: str = "",
    min_confidence: float = 0,
    q: str = "",
) -> list[DetectedCircuit]:
    """Filtra circuitos por parâmetros."""
    qs = DetectedCircuit.objects.select_related("snapshot__device")
    if circuit_type:
        qs = qs.filter(circuit_type=circuit_type)
    if device:
        qs = qs.filter(snapshot__device__name__icontains=device)
    if vendor:
        qs = qs.filter(snapshot__vendor=vendor)
    if min_confidence > 0:
        qs = qs.filter(details__confidence__gte=min_confidence)
    if q:
        qs = qs.filter(
            Q(details__interface__icontains=q)
            | Q(description__icontains=q)
            | Q(details__routed_prefix__icontains=q)
            | Q(details__vsi_name__icontains=q)
        )
    return list(qs.order_by("-created_at"))


def filter_services(
    service_type: str = "",
    device: str = "",
    vendor: str = "",
    min_confidence: float = 0,
    q: str = "",
) -> list[DetectedService]:
    """Filtra serviços por parâmetros."""
    qs = DetectedService.objects.select_related("snapshot__device")
    if service_type:
        qs = qs.filter(service_type=service_type)
    if device:
        qs = qs.filter(snapshot__device__name__icontains=device)
    if vendor:
        qs = qs.filter(snapshot__vendor=vendor)
    if min_confidence > 0:
        qs = qs.filter(confidence__gte=min_confidence)
    if q:
        qs = qs.filter(
            Q(name__icontains=q)
            | Q(description__icontains=q)
            | Q(metadata__icontains=q)
        )
    return list(qs.order_by("-confidence", "-created_at"))


def filter_issues(
    severity: str = "",
    code: str = "",
    device: str = "",
    vendor: str = "",
    q: str = "",
) -> list[AnalysisIssue]:
    """Filtra issues por parâmetros."""
    qs = AnalysisIssue.objects.select_related("snapshot__device")
    if severity:
        qs = qs.filter(severity=severity)
    if code:
        qs = qs.filter(code=code)
    if device:
        qs = qs.filter(snapshot__device__name__icontains=device)
    if vendor:
        qs = qs.filter(snapshot__vendor=vendor)
    if q:
        qs = qs.filter(
            Q(title__icontains=q)
            | Q(description__icontains=q)
            | Q(code__icontains=q)
        )
    # Order: critical first, then warning, then info
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    results = list(qs.all())
    results.sort(key=lambda x: (severity_order.get(x.severity, 99), -x.pk))
    return results
