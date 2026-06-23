from apps.analysis.models import ParsedConfig

from .models import DeviceLink, VlanDefinition, VlanEndpoint, VlanInterface, VlanPath, VlanTrackDevice, VlanTrackSession, VlanTrackingIssue
from .vlan_correlator import run_vlan_correlation


def create_session_from_devices(name, devices_snapshots, user=None, description=""):
    session = VlanTrackSession.objects.create(
        name=name, description=description, created_by=user
    )
    for order, (device, snapshot) in enumerate(devices_snapshots):
        pc = ParsedConfig.objects.filter(snapshot=snapshot).first()
        VlanTrackDevice.objects.create(
            session=session,
            device=device,
            snapshot=snapshot,
            parsed_config=pc,
            order=order,
        )
    return session


def run_session_analysis(session):
    run_vlan_correlation(session)


def get_session_summary(session):
    return {
        "total_devices": session.track_devices.count(),
        "total_links": DeviceLink.objects.filter(session=session).count(),
        "total_vlans": VlanDefinition.objects.filter(session=session).count(),
        "total_endpoints": VlanEndpoint.objects.filter(session=session).count(),
        "total_paths": VlanPath.objects.filter(session=session).count(),
        "total_issues": VlanTrackingIssue.objects.filter(session=session).count(),
        "top_vlans": list(
            VlanDefinition.objects.filter(session=session)
            .order_by("-device_count")[:10]
            .values("vlan_id", "name", "device_count", "interface_count")
        ),
        "links_by_confidence": {
            label: DeviceLink.objects.filter(session=session, confidence=key).count()
            for key, label in [("high", "Alta"), ("medium", "Média"), ("low", "Baixa")]
        },
    }


def get_vlan_path_summary(session, vlan_id):
    vdef = VlanDefinition.objects.filter(session=session, vlan_id=vlan_id).first()
    if not vdef:
        return None
    paths = VlanPath.objects.filter(session=session, vlan_definition=vdef).select_related(
        "from_device", "to_device", "via_link"
    )
    endpoints = VlanEndpoint.objects.filter(session=session, vlan_definition=vdef).select_related("device")
    interfaces = VlanInterface.objects.filter(session=session, vlan_id=vlan_id).select_related("device")
    issues = VlanTrackingIssue.objects.filter(session=session, vlan_definition=vdef)
    return {
        "definition": vdef,
        "paths": paths,
        "endpoints": endpoints,
        "interfaces": interfaces,
        "issues": issues,
    }
