"""Serviço operacional por dispositivo.

Fornece funções para consolidar dados de um único equipamento:
status operacional, resumo, timeline, ações recomendadas.
"""

from datetime import datetime

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


def get_device_status(device: Device) -> str:
    """Retorna status operacional do dispositivo.

    - 'critical': última análise tem issue de severidade 'critical'
    - 'warning': última análise tem issue de severidade 'warning'
    - 'ok': última análise sem issues
    - 'no_data': sem snapshots ou sem análise
    """
    last = ConfigSnapshot.objects.filter(device=device).order_by("-created_at", "-pk").first()
    if not last:
        return "no_data"
    parsed = ParsedConfig.objects.filter(snapshot=last).first()
    if not parsed:
        return "no_data"
    issues = AnalysisIssue.objects.filter(snapshot=last)
    if issues.filter(severity="critical").exists():
        return "critical"
    if issues.filter(severity="warning").exists():
        return "warning"
    return "ok"


def get_device_summary(device: Device) -> dict:
    """Retorna resumo consolidado de um dispositivo."""
    snapshots = list(ConfigSnapshot.objects.filter(device=device).order_by("-created_at", "-pk"))
    last_snap = snapshots[0] if snapshots else None
    last_parsed = ParsedConfig.objects.filter(snapshot=last_snap).first() if last_snap else None

    circuits = []
    services = []
    issues = []
    if last_parsed:
        circuits = list(DetectedCircuit.objects.filter(snapshot=last_snap))
        services = list(DetectedService.objects.filter(snapshot=last_snap))
        issues = list(AnalysisIssue.objects.filter(snapshot=last_snap).order_by("-severity"))

    # Comparisons where this device appears
    comparisons = list(
        ConfigComparison.objects.filter(
            Q(base_snapshot__device=device) | Q(target_snapshot__device=device)
        ).select_related("base_snapshot", "target_snapshot").order_by("-created_at")[:10]
    )

    critical_count = sum(1 for i in issues if i.severity == "critical")
    warning_count = sum(1 for i in issues if i.severity == "warning")
    info_count = sum(1 for i in issues if i.severity == "info")

    return {
        "device": device,
        "status": get_device_status(device),
        "snapshots": snapshots,
        "last_snapshot": last_snap,
        "last_parsed": last_parsed,
        "total_snapshots": len(snapshots),
        "circuits": circuits,
        "services": services,
        "issues": issues,
        "comparisons": comparisons,
        "critical_count": critical_count,
        "warning_count": warning_count,
        "info_count": info_count,
    }


def get_device_timeline(device: Device, limit: int = 20) -> list[dict]:
    """Retorna timeline de eventos do dispositivo."""
    events: list[dict] = []

    for snap in ConfigSnapshot.objects.filter(device=device).order_by("-created_at", "-pk")[:10]:
        events.append({
            "date": snap.created_at,
            "type": "snapshot",
            "label": f"Snapshot #{snap.pk} criado",
            "url": f"/configs/",
        })
        parsed = ParsedConfig.objects.filter(snapshot=snap).first()
        if parsed:
            events.append({
                "date": parsed.created_at,
                "type": "analysis",
                "label": f"Análise #{parsed.pk} executada",
                "url": f"/analysis/{parsed.pk}/",
            })
        for issue in AnalysisIssue.objects.filter(snapshot=snap, severity="critical")[:3]:
            events.append({
                "date": issue.created_at,
                "type": "critical_issue",
                "label": f"Issue crítica: {issue.title}",
                "url": f"/issues/{issue.pk}/",
            })

    for comp in ConfigComparison.objects.filter(
        Q(base_snapshot__device=device) | Q(target_snapshot__device=device)
    ).order_by("-created_at")[:10]:
        events.append({
            "date": comp.created_at,
            "type": "comparison",
            "label": f"Comparação #{comp.pk} criada",
            "url": f"/comparisons/{comp.pk}/",
        })

    events.sort(key=lambda e: e["date"], reverse=True)
    return events[:limit]


def get_device_recommended_actions(device: Device) -> list[dict]:
    """Gera ações recomendadas específicas do dispositivo."""
    actions: list[dict] = []
    last_snap = ConfigSnapshot.objects.filter(device=device).order_by("-created_at", "-pk").first()
    if not last_snap:
        return [{
            "action": "Criar primeira análise para este dispositivo.",
            "reason": "Nenhum snapshot analisado ainda.",
            "priority": "high",
        }]

    parsed = ParsedConfig.objects.filter(snapshot=last_snap).first()
    if not parsed:
        return [{
            "action": "Analisar snapshot mais recente deste dispositivo.",
            "reason": "O snapshot existe mas não foi analisado.",
            "priority": "high",
        }]

    issues = AnalysisIssue.objects.filter(snapshot=last_snap)
    circuits = DetectedCircuit.objects.filter(snapshot=last_snap)
    services = DetectedService.objects.filter(snapshot=last_snap)

    if issues.filter(severity="critical").exists():
        cnt = issues.filter(severity="critical").count()
        actions.append({
            "action": f"Priorizar correção das {cnt} issue(s) de alta severidade.",
            "reason": "Issues críticas representam riscos operacionais imediatos.",
            "priority": "high",
        })

    if issues.filter(code="interface_missing_description").exists():
        actions.append({
            "action": "Padronizar descriptions das interfaces físicas.",
            "reason": "Descriptions ausentes dificultam troubleshooting.",
            "priority": "medium",
        })

    if issues.filter(code="subinterface_missing_description").exists():
        actions.append({
            "action": "Adicionar descrição nas subinterfaces dot1q.",
            "reason": "Subinterfaces sem descrição dificultam identificar circuitos.",
            "priority": "medium",
        })

    if issues.filter(code="static_route_missing_description").exists():
        actions.append({
            "action": "Documentar rotas estáticas sem descrição.",
            "reason": "Rotas sem descrição dificultam auditoria.",
            "priority": "medium",
        })

    if issues.filter(code="static_route_unreachable_next_hop").exists():
        actions.append({
            "action": "Validar next-hops inalcançáveis em rotas estáticas.",
            "reason": "Next-hops inalcançáveis podem causar queda de serviço.",
            "priority": "high",
        })

    if services.filter(service_type__in=("bng", "radius", "aaa")).exists():
        actions.append({
            "action": "Validar periodicamente autenticação AAA/RADIUS deste equipamento.",
            "reason": "Serviços de autenticação são críticos para assinantes.",
            "priority": "medium",
        })

    if circuits.filter(circuit_type="l3_transit").exists():
        cnt = circuits.filter(circuit_type="l3_transit").count()
        actions.append({
            "action": f"Validar next-hops e prefixos roteados dos {cnt} circuito(s) L3.",
            "reason": "Prefixos roteados e next-hops devem ser documentados e alcançáveis.",
            "priority": "medium",
        })

    return actions


def filter_devices(vendor: str = "", status: str = "", q: str = "") -> list[dict]:
    """Retorna lista de dispositivos com dados operacionais, aplicando filtros."""
    qs = Device.objects.all()
    if vendor:
        qs = qs.filter(vendor=vendor)
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(hostname__icontains=q) | Q(ip_address__icontains=q))

    results = []
    for device in qs:
        status_val = get_device_status(device)
        if status and status != status_val:
            continue
        last_snap = ConfigSnapshot.objects.filter(device=device).order_by("-created_at", "-pk").first()
        last_parsed = ParsedConfig.objects.filter(snapshot=last_snap).first() if last_snap else None
        circuits_count = DetectedCircuit.objects.filter(snapshot=last_snap).count() if last_snap else 0
        services_count = DetectedService.objects.filter(snapshot=last_snap).count() if last_snap else 0
        issues_count = AnalysisIssue.objects.filter(snapshot=last_snap).count() if last_snap else 0

        results.append({
            "device": device,
            "status": status_val,
            "total_snapshots": ConfigSnapshot.objects.filter(device=device).count(),
            "last_snapshot_date": last_snap.created_at if last_snap else None,
            "last_snapshot": last_snap,
            "last_parsed": last_parsed,
            "circuits_count": circuits_count,
            "services_count": services_count,
            "issues_count": issues_count,
        })

    return results
