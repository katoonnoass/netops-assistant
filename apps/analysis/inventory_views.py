"""Views de inventário — circuitos, serviços, issues."""

import csv

from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render

from apps.analysis.models import (
    AnalysisIssue,
    DetectedCircuit,
    DetectedService,
    ParsedConfig,
)
from apps.analysis.operational import (
    filter_circuits,
    filter_issues,
    filter_services,
    get_latest_parsed_configs_by_device,
    get_operational_summary,
    get_recommended_actions,
)
from apps.config_archive.models import ConfigSnapshot


def inventory_circuit_list(request):
    circuit_type = request.GET.get("type", "")
    device = request.GET.get("device", "")
    vendor = request.GET.get("vendor", "")
    min_conf = request.GET.get("min_confidence", "")
    q = request.GET.get("q", "")
    try:
        min_conf = float(min_conf) if min_conf else 0
    except ValueError:
        min_conf = 0

    circuits = filter_circuits(
        circuit_type=circuit_type,
        device=device,
        vendor=vendor,
        min_confidence=min_conf,
        q=q,
    )

    circuit_type_choices = DetectedCircuit.CircuitType.choices
    vendor_choices = [("", "Todos")] + [
        (v, l) for v, l in [("huawei", "Huawei"), ("cisco", "Cisco"),
                            ("zte", "ZTE"), ("datacom", "Datacom"),
                            ("mikrotik", "MikroTik"), ("other", "Outro")]
    ]
    return render(request, "analysis/circuit_list.html", {
        "circuits": circuits,
        "circuit_type_choices": circuit_type_choices,
        "vendor_choices": vendor_choices,
        "filter_type": circuit_type,
        "filter_device": device,
        "filter_vendor": vendor,
        "filter_min_conf": min_conf,
        "filter_q": q,
    })


def inventory_circuit_detail(request, pk):
    circuit = get_object_or_404(
        DetectedCircuit.objects.select_related("snapshot__device"),
        pk=pk,
    )
    parsed = ParsedConfig.objects.filter(snapshot=circuit.snapshot).first()

    # Validation commands by circuit type
    commands = _circuit_validation_commands(circuit)

    return render(request, "analysis/circuit_detail.html", {
        "circuit": circuit,
        "parsed": parsed,
        "commands": commands,
    })


def inventory_circuit_export(request):
    circuit_type = request.GET.get("type", "")
    circuits = filter_circuits(circuit_type=circuit_type)
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="circuits.csv"'
    w = csv.writer(response)
    w.writerow(["pk", "device", "vendor", "type", "interface", "vlan", "routed_prefix",
                 "vsi_name", "confidence", "description", "created_at"])
    for c in circuits:
        d = c.details
        w.writerow([
            c.pk,
            c.snapshot.device.name if c.snapshot.device else "",
            c.snapshot.vendor,
            c.circuit_type,
            d.get("interface", ""),
            d.get("vlan_id", ""),
            d.get("routed_prefix", ""),
            d.get("vsi_name", ""),
            d.get("confidence", ""),
            c.description,
            c.created_at.isoformat(),
        ])
    return response


def inventory_service_list(request):
    service_type = request.GET.get("type", "")
    device = request.GET.get("device", "")
    vendor = request.GET.get("vendor", "")
    min_conf = request.GET.get("min_confidence", "")
    q = request.GET.get("q", "")
    try:
        min_conf = float(min_conf) if min_conf else 0
    except ValueError:
        min_conf = 0

    services = filter_services(
        service_type=service_type,
        device=device,
        vendor=vendor,
        min_confidence=min_conf,
        q=q,
    )
    service_type_choices = DetectedService.ServiceType.choices
    vendor_choices = [("", "Todos")] + [
        (v, l) for v, l in [("huawei", "Huawei"), ("cisco", "Cisco"),
                            ("zte", "ZTE"), ("datacom", "Datacom"),
                            ("mikrotik", "MikroTik"), ("other", "Outro")]
    ]
    return render(request, "analysis/service_list.html", {
        "services": services,
        "service_type_choices": service_type_choices,
        "vendor_choices": vendor_choices,
        "filter_type": service_type,
        "filter_device": device,
        "filter_vendor": vendor,
        "filter_min_conf": min_conf,
        "filter_q": q,
    })


def inventory_service_detail(request, pk):
    svc = get_object_or_404(
        DetectedService.objects.select_related("snapshot__device"),
        pk=pk,
    )
    commands = _service_validation_commands(svc)
    return render(request, "analysis/service_detail.html", {
        "service": svc,
        "commands": commands,
    })


def inventory_service_export(request):
    service_type = request.GET.get("type", "")
    services = filter_services(service_type=service_type)
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="services.csv"'
    w = csv.writer(response)
    w.writerow(["pk", "device", "vendor", "service_type", "name", "confidence",
                 "description", "created_at"])
    for s in services:
        w.writerow([
            s.pk,
            s.snapshot.device.name if s.snapshot.device else "",
            s.snapshot.vendor,
            s.service_type,
            s.name,
            s.confidence,
            s.description,
            s.created_at.isoformat(),
        ])
    return response


def inventory_issue_list(request):
    severity = request.GET.get("severity", "")
    code = request.GET.get("code", "")
    device = request.GET.get("device", "")
    vendor = request.GET.get("vendor", "")
    q = request.GET.get("q", "")

    issues = filter_issues(
        severity=severity,
        code=code,
        device=device,
        vendor=vendor,
        q=q,
    )
    vendor_choices = [("", "Todos")] + [
        (v, l) for v, l in [("huawei", "Huawei"), ("cisco", "Cisco"),
                            ("zte", "ZTE"), ("datacom", "Datacom"),
                            ("mikrotik", "MikroTik"), ("other", "Outro")]
    ]
    return render(request, "analysis/issue_list.html", {
        "issues": issues,
        "vendor_choices": vendor_choices,
        "filter_severity": severity,
        "filter_code": code,
        "filter_device": device,
        "filter_vendor": vendor,
        "filter_q": q,
    })


def inventory_issue_detail(request, pk):
    issue = get_object_or_404(
        AnalysisIssue.objects.select_related("snapshot__device"),
        pk=pk,
    )
    parsed = ParsedConfig.objects.filter(snapshot=issue.snapshot).first()
    suggestion = _issue_corrective_suggestion(issue)
    return render(request, "analysis/issue_detail.html", {
        "issue": issue,
        "parsed": parsed,
        "suggestion": suggestion,
    })


def inventory_issue_export(request):
    severity = request.GET.get("severity", "")
    code = request.GET.get("code", "")
    issues = filter_issues(severity=severity, code=code)
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="issues.csv"'
    w = csv.writer(response)
    w.writerow(["pk", "device", "vendor", "severity", "code", "title",
                 "description", "created_at"])
    for issue in issues:
        w.writerow([
            issue.pk,
            issue.snapshot.device.name if issue.snapshot.device else "",
            issue.snapshot.vendor,
            issue.severity,
            issue.code,
            issue.title,
            issue.description,
            issue.created_at.isoformat(),
        ])
    return response


# ── Helpers ─────────────────────────────────────────────────────────


def _circuit_validation_commands(circuit: DetectedCircuit) -> list[str]:
    d = circuit.details
    t = circuit.circuit_type
    cmds = []
    iface = d.get("interface", "?")
    cmds.append(f"display interface {iface}")
    cmds.append(f"display current-configuration interface {iface}")
    if t in ("l3_transit",):
        rp = d.get("routed_prefix", "")
        if rp:
            cmds.append(f"display ip routing-table {rp.split('/')[0]}")
        lip = d.get("local_ip", "")
        rip = d.get("remote_ip", "")
        if lip and rip:
            cmds.append(f"ping -a {lip} {rip}")
    elif t in ("vlan_transport",):
        cmds.append("display vlan")
    elif t in ("qinq_transport", "qinq"):
        cmds.append("display vlan")
    elif t in ("l2vpn_vsi",):
        vsi = d.get("vsi_name", "")
        if vsi:
            cmds.append(f"display vsi name {vsi}")
        cmds.append("display mpls l2vc")
    return cmds


def _service_validation_commands(svc: DetectedService) -> list[str]:
    t = svc.service_type
    if t == "bng":
        return [
            "display access-user",
            "display access-user domain",
            "display aaa online-fail-record",
            "display current-configuration configuration aaa",
        ]
    elif t == "radius":
        return [
            "display radius-server configuration",
            "display current-configuration | include radius",
            "display aaa online-fail-record",
        ]
    elif t == "ip_pool":
        name = svc.name or ""
        cmds = ["display ip pool"]
        if name and name != "ip-pool":
            cmds.append(f"display ip pool name {name}")
        cmds.append("display access-user domain")
        return cmds
    elif t == "aaa":
        return [
            "display current-configuration configuration aaa",
            "display domain",
        ]
    elif t == "subscriber_access":
        return [
            "display access-user",
            "display current-configuration configuration bas",
        ]
    return ["display current-configuration"]


def _issue_corrective_suggestion(issue: AnalysisIssue) -> str:
    code = issue.code
    suggestions = {
        "interface_missing_description": (
            "Adicionar description padronizada na interface, "
            "identificando o link, cliente ou serviço associado."
        ),
        "subinterface_missing_description": (
            "Adicionar description na subinterface informando "
            "o cliente, tipo de circuito e VLAN associada."
        ),
        "static_route_missing_description": (
            "Adicionar description na rota informando o cliente, "
            "circuito ou finalidade da rota."
        ),
        "bgp_peer_missing_description": (
            "Adicionar description no peer BGP identificando "
            "o AS vizinho, cliente ou contrato."
        ),
        "static_route_unreachable_next_hop": (
            "Validar se existe interface conectada para o next-hop "
            "ou rota intermediária que o torne alcançável."
        ),
    }
    return suggestions.get(code, "Revisar a issue e tomar ação corretiva conforme políticas da rede.")
