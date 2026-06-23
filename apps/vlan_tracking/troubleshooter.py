from .models import (
    DeviceLink,
    VlanDefinition,
    VlanEndpoint,
    VlanInterface,
    VlanPath,
    VlanTrackDevice,
    VlanTrackingIssue,
)
from .presentation import get_link_vlan_ids

VENDOR_COMMANDS = {
    "huawei": {
        "interface": [
            "display current-configuration interface {interface}",
            "display this interface {interface}",
            "display port vlan interface {interface}",
        ],
        "vlan": [
            "display vlan {vlan_id}",
            "display mac-address vlan {vlan_id}",
        ],
        "lldp": [
            "display lldp neighbor interface {interface}",
        ],
        "subinterface": [
            "display current-configuration interface {interface}",
            "display ip interface brief | include {interface}",
            "display arp interface {interface}",
        ],
        "l2vpn": [
            "display vsi",
            "display vsi name {vsi}",
            "display mpls l2vc",
        ],
        "bas": [
            "display access-user interface {interface}",
            "display access-user vlan {vlan_id}",
            "display aaa configuration",
        ],
    },
    "cisco": {
        "interface": [
            "show running-config interface {interface}",
            "show interfaces {interface}",
        ],
        "vlan": [
            "show vlan id {vlan_id}",
            "show mac address-table vlan {vlan_id}",
            "show interfaces trunk",
        ],
        "lldp": [
            "show lldp neighbors {interface} detail",
        ],
        "subinterface": [
            "show running-config interface {interface}",
            "show ip interface brief | include {interface}",
        ],
    },
}


def _get_vendor(device):
    return getattr(device, "vendor", "unknown") or "unknown"


def _get_vlan_vsi_name(session, vlan_id):
    """Get VSI name from interfaces for this VLAN."""
    for vi in VlanInterface.objects.filter(session=session, vlan_id=vlan_id, source="vsi"):
        raw = vi.description or ""
        if "VSI:" in raw:
            return raw.split("VSI:")[-1].strip()
    return None


def classify_vlan_health(session, vlan_id):
    vdef = VlanDefinition.objects.filter(session=session, vlan_id=vlan_id).first()
    if not vdef:
        return {"status": "no_data", "label": "Sem dados", "reason": "VLAN não encontrada na sessão", "severity_score": 0}

    endpoints = VlanEndpoint.objects.filter(session=session, vlan_definition=vdef)
    paths = VlanPath.objects.filter(session=session, vlan_definition=vdef)
    issues = VlanTrackingIssue.objects.filter(session=session, vlan_definition=vdef)
    interfaces = VlanInterface.objects.filter(session=session, vlan_id=vlan_id)
    devices = interfaces.values("device").distinct().count()

    # Crítico
    if endpoints.exists() and not paths.exists():
        return {"status": "critical", "label": "Crítico", "reason": "Endpoint sem caminho L2", "severity_score": 90}
    has_missing = issues.filter(code="vlan_on_trunk_missing_on_neighbor").exists()
    if has_missing and not paths.exists():
        return {"status": "critical", "label": "Crítico", "reason": "VLAN ausente no vizinho sem path alternativo", "severity_score": 85}

    # Atenção
    if issues.filter(code="vlan_path_uses_low_confidence_link").exists():
        return {"status": "attention", "label": "Atenção", "reason": "Caminho usa link de baixa confiança", "severity_score": 40}
    if issues.filter(code="vlan_defined_but_not_used").exists():
        return {"status": "attention", "label": "Atenção", "reason": "VLAN definida mas não usada", "severity_score": 30}
    if endpoints.count() > 1 and paths.count() == 0:
        return {"status": "attention", "label": "Atenção", "reason": "Múltiplos endpoints sem caminho entre eles", "severity_score": 50}

    # Incompleto
    if devices <= 1:
        return {"status": "incomplete", "label": "Incompleto", "reason": "VLAN aparece em apenas um dispositivo", "severity_score": 20}

    # OK
    if endpoints.exists() and paths.exists():
        return {"status": "ok", "label": "OK", "reason": "VLAN com path coerente e sem issues críticas", "severity_score": 0}

    return {"status": "incomplete", "label": "Incompleto", "reason": "Dados insuficientes", "severity_score": 10}


def build_vlan_validation_commands(session, vlan_id):
    commands = []
    vdef = VlanDefinition.objects.filter(session=session, vlan_id=vlan_id).first()
    if not vdef:
        return commands

    interfaces = VlanInterface.objects.filter(session=session, vlan_id=vlan_id).select_related("device")

    for vi in interfaces:
        device = vi.device
        vendor = _get_vendor(device)
        cmds = VENDOR_COMMANDS.get(vendor, VENDOR_COMMANDS.get("huawei", {}))
        device_commands = []

        # VLAN commands
        for templ in cmds.get("vlan", []):
            device_commands.append(templ.format(vlan_id=vlan_id, interface=vi.interface_name))

        # Interface commands
        for templ in cmds.get("interface", []):
            device_commands.append(templ.format(interface=vi.interface_name, vlan_id=vlan_id))

        # LLDP
        for templ in cmds.get("lldp", []):
            device_commands.append(templ.format(interface=vi.interface_name))

        # Subinterface
        if vi.port_mode == "subinterface":
            for templ in cmds.get("subinterface", []):
                device_commands.append(templ.format(interface=vi.interface_name, vlan_id=vlan_id))

        # L2VPN
        if vi.port_mode == "l2vpn":
            vsi_name = _get_vlan_vsi_name(session, vlan_id)
            for templ in cmds.get("l2vpn", []):
                device_commands.append(templ.format(vsi=vsi_name or ""))

        # BAS
        if vi.port_mode == "bas":
            for templ in cmds.get("bas", []):
                device_commands.append(templ.format(interface=vi.interface_name, vlan_id=vlan_id))

        if device_commands:
            commands.append({
                "device": device.name,
                "vendor": vendor,
                "interface": vi.interface_name,
                "commands": device_commands,
            })

    return commands


def build_vlan_issue_recommendations(session, vlan_id):
    vdef = VlanDefinition.objects.filter(session=session, vlan_id=vlan_id).first()
    if not vdef:
        return []
    issues = VlanTrackingIssue.objects.filter(session=session, vlan_definition=vdef)
    recommendations = []

    REC_MAP = {
        "vlan_on_trunk_missing_on_neighbor": [
            "Validar se a VLAN está liberada nos dois lados do trunk.",
            "Conferir allowed VLAN / port trunk allow-pass vlan.",
            "Conferir se o link correto foi identificado.",
        ],
        "vlan_endpoint_without_path": [
            "Verificar se existe trunk transportando a VLAN até o endpoint.",
            "Verificar link manual/LLDP entre equipamentos.",
        ],
        "vlan_path_uses_low_confidence_link": [
            "Confirmar enlace por LLDP ou cadastrar link manual.",
            "Validar se a subrede /29 realmente representa interligação ponto-a-ponto.",
        ],
        "subinterface_vlan_without_l2_path": [
            "Subinterface L3 encontrada, mas caminho L2 até ela não foi identificado.",
            "Validar trunks intermediários.",
        ],
        "vlan_defined_but_not_used": [
            "VLAN declarada, mas sem interface associada.",
            "Pode ser reserva ou lixo de configuração.",
        ],
    }

    for issue in issues:
        recs = REC_MAP.get(issue.code, ["Investigar causa da issue."])
        recommendations.append({
            "code": issue.code,
            "title": issue.title,
            "severity": issue.severity,
            "recommendations": recs,
        })

    return recommendations


def build_vlan_endpoint_summary(session, vlan_id):
    vdef = VlanDefinition.objects.filter(session=session, vlan_id=vlan_id).first()
    if not vdef:
        return {}
    endpoints = VlanEndpoint.objects.filter(session=session, vlan_definition=vdef).select_related("device")
    summary = {"access": [], "subinterface_l3": [], "l2vpn_vsi": [], "bas": [], "qinq_edge": [], "unknown": []}
    for ep in endpoints:
        etype = ep.endpoint_type
        entry = {
            "device": ep.device.name,
            "interface": ep.interface_name,
            "description": ep.description,
        }
        if etype in summary:
            summary[etype].append(entry)
        else:
            summary["unknown"].append(entry)
    return summary


def build_vlan_path_risk_summary(session, vlan_id):
    vdef = VlanDefinition.objects.filter(session=session, vlan_id=vlan_id).first()
    if not vdef:
        return {}
    paths = VlanPath.objects.filter(session=session, vlan_definition=vdef).select_related("via_link")
    low_conf = 0
    medium_conf = 0
    high_conf = 0
    for p in paths:
        if p.via_link:
            if p.via_link.confidence == "low":
                low_conf += 1
            elif p.via_link.confidence == "medium":
                medium_conf += 1
            else:
                high_conf += 1
    return {
        "total": paths.count(),
        "high_confidence": high_conf,
        "medium_confidence": medium_conf,
        "low_confidence": low_conf,
        "has_risk": low_conf > 0,
    }


def build_vlan_troubleshooting_report(session, vlan_id):
    vdef = VlanDefinition.objects.filter(session=session, vlan_id=vlan_id).first()
    if not vdef:
        return {"error": f"VLAN {vlan_id} não encontrada na sessão."}

    interfaces = VlanInterface.objects.filter(session=session, vlan_id=vlan_id).select_related("device")
    paths = VlanPath.objects.filter(session=session, vlan_definition=vdef).select_related(
        "from_device", "to_device", "via_link"
    )
    issues = VlanTrackingIssue.objects.filter(session=session, vlan_definition=vdef)
    links = DeviceLink.objects.filter(session=session, id__in=paths.values("via_link")).select_related("device_a", "device_b")

    health = classify_vlan_health(session, vlan_id)
    endpoint_summary = build_vlan_endpoint_summary(session, vlan_id)
    recommendations = build_vlan_issue_recommendations(session, vlan_id)
    validation_commands = build_vlan_validation_commands(session, vlan_id)
    risk = build_vlan_path_risk_summary(session, vlan_id)

    device_names = list(interfaces.values_list("device__name", flat=True).distinct().order_by())

    path_data = []
    for p in paths:
        method_label = ""
        confidence_label = ""
        if p.via_link:
            method_label = p.via_link.get_discovery_method_display()
            confidence_label = p.via_link.get_confidence_display()
        path_data.append({
            "from_device": p.from_device.name,
            "from_interface": p.from_interface,
            "to_device": p.to_device.name,
            "to_interface": p.to_interface,
            "method": method_label,
            "confidence": confidence_label,
            "tagged": p.tagged,
            "low_confidence": p.via_link and p.via_link.confidence == "low",
        })

    return {
        "session": {"id": session.pk, "name": session.name},
        "vlan": {"id": vdef.vlan_id, "name": vdef.name, "description": vdef.description},
        "health": health,
        "devices": device_names,
        "interfaces": list(interfaces.values("device__name", "interface_name", "port_mode", "tagged")),
        "paths": path_data,
        "endpoints": endpoint_summary,
        "issues": list(issues.values("severity", "code", "title", "description")),
        "recommendations": recommendations,
        "validation_commands": validation_commands,
        "risk": risk,
    }


def export_vlan_report_text(session, vlan_id):
    report = build_vlan_troubleshooting_report(session, vlan_id)
    if "error" in report:
        return report["error"]

    lines = []
    lines.append(f"Relatório VLAN {report['vlan']['id']} — Sessão {report['session']['name']}")
    lines.append("=" * 60)
    lines.append(f"Status: {report['health']['label']}")
    lines.append(f"Motivo: {report['health']['reason']}")
    lines.append("")

    lines.append(f"Dispositivos ({len(report['devices'])}):")
    for d in report["devices"]:
        lines.append(f"  - {d}")
    lines.append("")

    lines.append("Endpoints:")
    for etype, entries in report["endpoints"].items():
        if entries:
            lines.append(f"  {etype} ({len(entries)}):")
            for ep in entries:
                desc = f" ({ep['description']})" if ep["description"] else ""
                lines.append(f"    {ep['device']}:{ep['interface']}{desc}")
    lines.append("")

    lines.append(f"Caminho ({len(report['paths'])} saltos):")
    for i, p in enumerate(report["paths"], 1):
        risk = " ⚠ baixa confiança" if p["low_confidence"] else ""
        lines.append(f"  {i}. {p['from_device']} {p['from_interface']} -> {p['to_device']} {p['to_interface']} via {p['method']}/{p['confidence']}{risk}")
    lines.append("")

    lines.append(f"Issues ({len(report['issues'])}):")
    for issue in report["issues"]:
        lines.append(f"  [{issue['severity']}] {issue['code']}: {issue['title']}")
    lines.append("")

    lines.append("Recomendações:")
    for rec in report["recommendations"]:
        for r in rec["recommendations"]:
            lines.append(f"  - {r}")
    lines.append("")

    lines.append("Comandos sugeridos:")
    for cmd_group in report["validation_commands"]:
        lines.append(f"  {cmd_group['device']} (vendor: {cmd_group['vendor']}):")
        for cmd in cmd_group["commands"]:
            lines.append(f"    # {cmd}")

    return "\n".join(lines)


def export_vlan_report_csv_rows(session, vlan_id):
    report = build_vlan_troubleshooting_report(session, vlan_id)
    if "error" in report:
        return [{"section": "error", "description": report["error"]}]

    rows = []
    for d in report["devices"]:
        rows.append({"section": "device", "device": d, "interface": "", "vlan_id": vlan_id, "type": "device", "status": report["health"]["label"], "severity": "", "description": "", "command": ""})

    for etype, entries in report["endpoints"].items():
        for ep in entries:
            rows.append({"section": "endpoint", "device": ep["device"], "interface": ep["interface"], "vlan_id": vlan_id, "type": etype, "status": "", "severity": "", "description": ep.get("description", ""), "command": ""})

    for p in report["paths"]:
        rows.append({"section": "path", "device": f"{p['from_device']} -> {p['to_device']}", "interface": f"{p['from_interface']} -> {p['to_interface']}", "vlan_id": vlan_id, "type": "link", "status": "", "severity": "low" if p["low_confidence"] else "", "description": f"{p['method']}/{p['confidence']}", "command": ""})

    for issue in report["issues"]:
        rows.append({"section": "issue", "device": "", "interface": "", "vlan_id": vlan_id, "type": issue["code"], "status": "", "severity": issue["severity"], "description": issue["title"], "command": ""})

    for cmd_group in report["validation_commands"]:
        for cmd in cmd_group["commands"]:
            rows.append({"section": "command", "device": cmd_group["device"], "interface": cmd_group.get("interface", ""), "vlan_id": vlan_id, "type": f"vendor:{cmd_group['vendor']}", "status": "", "severity": "", "description": "", "command": cmd})

    return rows
