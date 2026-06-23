import html
import math

from .models import DeviceLink, VlanDefinition, VlanEndpoint, VlanPath, VlanTrackingIssue
from .presentation import get_link_vlan_ids

NODE_RADIUS = 30
NODE_GAP_X = 180
NODE_GAP_Y = 120
SVG_WIDTH = 1200
SVG_HEIGHT = 700
PADDING = 60


def _sanitize(value):
    return html.escape(str(value or ""))


def _get_positions_circular(devices, center_x, center_y, radius):
    n = len(devices)
    positions = {}
    for i, (dev_id, dev_name) in enumerate(devices):
        angle = 2 * math.pi * i / n - math.pi / 2
        x = center_x + radius * math.cos(angle)
        y = center_y + radius * math.sin(angle)
        positions[dev_id] = (x, y)
    return positions


def _get_positions_grid(devices, start_x, start_y):
    positions = {}
    cols = max(1, int(math.sqrt(len(devices) * 2)))
    for i, (dev_id, dev_name) in enumerate(devices):
        col = i % cols
        row = i // cols
        x = start_x + col * NODE_GAP_X
        y = start_y + row * NODE_GAP_Y
        positions[dev_id] = (x, y)
    return positions


def calculate_node_positions(session, link_data):
    device_set = {}
    for item in link_data:
        device_set[item["device_a_id"]] = item["device_a_name"]
        device_set[item["device_b_id"]] = item["device_b_name"]
    devices = list(device_set.items())
    if not devices:
        return {}, []

    center_x = SVG_WIDTH / 2
    center_y = SVG_HEIGHT / 2

    if len(devices) <= 8:
        radius = min(SVG_WIDTH, SVG_HEIGHT) / 3
        positions = _get_positions_circular(devices, center_x, center_y, radius)
    else:
        start_x = PADDING
        start_y = PADDING + 40
        positions = _get_positions_grid(devices, start_x, start_y)

    return positions, devices


def _build_link_issues_map(session, link_ids):
    issues = VlanTrackingIssue.objects.filter(
        session=session,
        code__in=[
            "vlan_path_uses_low_confidence_link",
            "vlan_on_trunk_missing_on_neighbor",
        ],
    )
    link_issues = {}
    for issue in issues:
        key = (issue.device_id, issue.interface_name)
        link_issues.setdefault(key, []).append(issue)
    return link_issues


def build_svg_topology(session, vlan_id=None, method=None, confidence=None, device=None, status=None):
    from .presentation import get_link_display_data

    filters = {k: v for k, v in [("method", method), ("confidence", confidence),
                                  ("device", device), ("vlan", vlan_id), ("status", status)] if v}
    link_data = get_link_display_data(session, filters)
    positions, devices = calculate_node_positions(session, link_data)

    # Build node metadata from links
    node_metadata = {}
    for item in link_data:
        for dev_id, dev_name in [(item["device_a_id"], item["device_a_name"]),
                                  (item["device_b_id"], item["device_b_name"])]:
            if dev_id not in node_metadata:
                node_metadata[dev_id] = {
                    "name": dev_name,
                    "vlan_ids": set(),
                    "issue_count": 0,
                    "endpoint_types": set(),
                }
            node_metadata[dev_id]["vlan_ids"].update(item["vlan_ids"])
            if item["issue_count"]:
                node_metadata[dev_id]["issue_count"] += 1

    # Add endpoint info if filtered by VLAN (also include devices from endpoints not in links)
    if vlan_id:
        endpoints = VlanEndpoint.objects.filter(
            session=session, vlan_definition__vlan_id=vlan_id
        ).select_related("device")
        for ep in endpoints:
            if ep.device_id not in node_metadata:
                node_metadata[ep.device_id] = {
                    "name": ep.device.name,
                    "vlan_ids": {vlan_id},
                    "issue_count": 0,
                    "endpoint_types": set(),
                }
            node_metadata[ep.device_id]["endpoint_types"].add(ep.endpoint_type)

    # Ensure all devices from metadata appear in positions
    from .presentation import _get_totals
    for dev_id in node_metadata:
        if dev_id not in positions:
            # Find existing position or add at a default location
            all_devs = list(positions.items())
            if all_devs:
                last_x = max(p[0] for p in positions.values()) + NODE_GAP_X
                last_y = PADDING + 40
                positions[dev_id] = (last_x, last_y)
            else:
                positions[dev_id] = (SVG_WIDTH / 2, SVG_HEIGHT / 2)

    stats = {
        "total_nodes": len(devices),
        "total_edges": len(link_data),
        "vlan_id": vlan_id,
    }

    svg = _render_svg(session, positions, link_data, node_metadata, vlan_id, filters)
    return {
        "svg": svg,
        "nodes": devices,
        "edges": link_data,
        "width": SVG_WIDTH,
        "height": SVG_HEIGHT,
        "filters": filters,
        "stats": stats,
    }


def _render_svg(session, positions, link_data, node_metadata, vlan_id, filters):
    lines = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {} {}" width="100%" height="100%">'.format(SVG_WIDTH, SVG_HEIGHT)]
    lines.append('<defs>')
    lines.append('<marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">'
                 '<polygon points="0 0, 10 3.5, 0 7" fill="#666"/></marker>')
    lines.append('</defs>')
    lines.append(f'<rect width="{SVG_WIDTH}" height="{SVG_HEIGHT}" fill="#fafafa" rx="8"/>')
    lines.append(f'<text x="{PADDING}" y="25" font-family="monospace" font-size="14" fill="#333">'
                 f'Topologia: {_sanitize(session.name)}</text>')

    # Draw edges
    for item in link_data:
        x1, y1 = positions.get(item["device_a_id"], (0, 0))
        x2, y2 = positions.get(item["device_b_id"], (0, 0))
        confidence_class = f"svg-link-{item['confidence']}"
        method_class = f"svg-method-{item['method']}"
        issue_class = "svg-link-has-issue" if item["issue_count"] > 0 else ""
        classes = f"svg-link {confidence_class} {method_class} {issue_class}"
        lines.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" class="{classes}" '
            f'stroke-width="2.5" marker-end="url(#arrowhead)"/>'
        )
        # Link label at midpoint (sanitize only once on the final string)
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2 - 15
        label = f"{item['interface_a']} ↔ {item['interface_b']} | {item['method_label']}/{item['confidence_label']}"
        if item["vlan_ids"]:
            label += f" | VLANs: {','.join(str(v) for v in item['vlan_ids'][:5])}"
        if item["issue_count"] > 0:
            label += " ⚠"
        lines.append(
            f'<text x="{mx}" y="{my}" text-anchor="middle" font-family="monospace" font-size="10" fill="#555" '
            f'class="svg-link-label">{_sanitize(label)}</text>'
        )

    # Draw nodes
    for dev_id, (x, y) in positions.items():
        meta = node_metadata.get(dev_id, {})
        name = _sanitize(meta.get("name", f"Device {dev_id}"))
        vlan_count = len(meta.get("vlan_ids", set()))
        issue_count = meta.get("issue_count", 0)
        endpoint_types = meta.get("endpoint_types", set())

        # Node circle
        node_color = "#4a90d9"
        if vlan_id and endpoint_types:
            node_color = "#28a745"  # green if it has endpoints for this VLAN
        lines.append(
            f'<circle cx="{x}" cy="{y}" r="{NODE_RADIUS}" fill="{node_color}" stroke="#fff" stroke-width="2" '
            f'class="svg-node"/>'
        )
        # Device name (use raw name, not pre-sanitized)
        raw_name = meta.get("name", f"Device {dev_id}")
        lines.append(
            f'<text x="{x}" y="{y + 4}" text-anchor="middle" font-family="monospace" font-size="11" '
            f'fill="#fff" font-weight="bold" class="svg-node-text">{_sanitize(raw_name[:20])}</text>'
        )
        # Info below node
        info_y = y + NODE_RADIUS + 14
        info_parts = []
        if vlan_count > 0:
            info_parts.append(f"{vlan_count} VLANs")
        if issue_count > 0:
            info_parts.append(f"{issue_count} issues")
        if info_parts:
            lines.append(
                f'<text x="{x}" y="{info_y}" text-anchor="middle" font-family="monospace" font-size="9" '
                f'fill="#777">{_sanitize(" | ".join(info_parts))}</text>'
            )

        # Endpoint markers if filtered by VLAN
        if vlan_id and endpoint_types:
            ep_y = y - NODE_RADIUS - 10
            marker_symbols = {
                "access": "●",
                "subinterface_l3": "■",
                "l2vpn_vsi": "◆",
                "bas": "▲",
            }
            markers = []
            for etype in endpoint_types:
                sym = marker_symbols.get(etype, "?")
                markers.append(sym)
            if markers:
                lines.append(
                    f'<text x="{x}" y="{ep_y}" text-anchor="middle" font-family="monospace" font-size="14" '
                    f'fill="#28a745">{_sanitize("".join(markers))}</text>'
                )

    # Legend
    legend_x = SVG_WIDTH - 200
    legend_y = SVG_HEIGHT - 120
    lines.append(f'<rect x="{legend_x}" y="{legend_y}" width="190" height="110" fill="#fff" '
                 f'stroke="#ddd" rx="4" class="svg-legend"/>')
    lines.append(f'<text x="{legend_x + 8}" y="{legend_y + 18}" font-family="monospace" font-size="11" '
                 f'font-weight="bold" fill="#333">Legenda</text>')
    legend_items = [
        ("high", "#28a745", "Alta confiança"),
        ("medium", "#ffc107", "Média confiança"),
        ("low", "#dc3545", "Baixa confiança"),
    ]
    for i, (key, color, label) in enumerate(legend_items):
        ly = legend_y + 35 + i * 22
        lines.append(f'<line x1="{legend_x + 8}" y1="{ly}" x2="{legend_x + 38}" y2="{ly}" '
                     f'stroke="{color}" stroke-width="3"/>')
        lines.append(f'<text x="{legend_x + 45}" y="{ly + 4}" font-family="monospace" font-size="10" '
                     f'fill="#555">{_sanitize(label)}</text>')

    lines.append('</svg>')
    return "\n".join(lines)
