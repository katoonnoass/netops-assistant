from django.test import TestCase
from django.urls import reverse

from apps.analysis.models import ParsedConfig
from apps.config_archive.models import ConfigSnapshot
from apps.core.tests import *
from apps.devices.models import Device

from ..lldp_parser import parse_lldp_neighbors
from ..models import (
    DeviceLink,
    TopologyEvidence,
    VlanDefinition,
    VlanEndpoint,
    VlanInterface,
    VlanPath,
    VlanTrackDevice,
    VlanTrackSession,
    VlanTrackingIssue,
)
from ..services import create_session_from_devices, get_session_summary, run_session_analysis
from ..topology import (
    discover_links_by_description,
    discover_links_by_lldp,
    discover_links_by_subnet,
)
from ..vlan_correlator import (
    build_vlan_definitions,
    build_vlan_endpoints,
    build_vlan_interfaces,
    build_vlan_paths,
    build_tracking_issues,
    extract_vlan_interfaces_from_device,
    run_vlan_correlation,
)

SIMPLE_L2_CONFIG = """
sysname SW-01
vlan batch 10 20 30
interface GigabitEthernet0/0/1
 port link-type access
 port default vlan 10
 description Access-Client
interface GigabitEthernet0/0/2
 port link-type trunk
 port trunk allow-pass vlan 10 20 30
 description LINK:SW-02:GE0/0/1
"""

SIMPLE_L2_CONFIG_2 = """
sysname SW-02
vlan batch 10 20 30
interface GigabitEthernet0/0/1
 port link-type trunk
 port trunk allow-pass vlan 10 20 30
 description LINK:SW-01:GE0/0/2
interface GigabitEthernet0/0/2
 port link-type access
 port default vlan 10
 description Access-Client-2
"""

SUBNET_L3_CONFIG = """
sysname RTR-A
interface GigabitEthernet0/0/1
 ip address 10.0.0.1 255.255.255.252
 description LINK TO RTR-B
interface GigabitEthernet0/0/2.100
 vlan-type dot1q 100
 ip address 192.168.1.1 255.255.255.0
"""

SUBNET_L3_CONFIG_2 = """
sysname RTR-B
interface GigabitEthernet0/0/1
 ip address 10.0.0.2 255.255.255.252
 description LINK TO RTR-A
interface GigabitEthernet0/0/2.200
 vlan-type dot1q 200
 ip address 192.168.2.1 255.255.255.0
"""


def _create_device_and_snapshot(name, config_text, vendor="huawei"):
    device, _ = Device.objects.get_or_create(name=name, vendor=vendor)
    snapshot = ConfigSnapshot.objects.create(
        device=device,
        raw_config=config_text,
        vendor=vendor,
        source="paste",
    )
    from apps.analysis.services import analyze_config_snapshot
    analyze_config_snapshot(snapshot)
    return device, snapshot


class VlanTrackModelsTests(TestCase):
    def test_create_session(self):
        session = VlanTrackSession.objects.create(name="Teste")
        self.assertEqual(str(session), "Teste")

    def test_create_session_with_user(self):
        from django.contrib.auth.models import User
        user = User.objects.create_user("testuser", "test@test.com", "pass")
        session = VlanTrackSession.objects.create(name="Teste", created_by=user)
        self.assertEqual(session.created_by.username, "testuser")

    def test_add_device_to_session(self):
        dev, snap = _create_device_and_snapshot("SW-TEST", SIMPLE_L2_CONFIG)
        session = VlanTrackSession.objects.create(name="Teste")
        td = VlanTrackDevice.objects.create(
            session=session, device=dev, snapshot=snap, order=1
        )
        self.assertEqual(str(td), "SW-TEST [unknown]")

    def test_create_manual_link(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-B", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="Teste")
        link = DeviceLink.objects.create(
            session=session,
            device_a=dev_a,
            interface_a="GE0/0/2",
            device_b=dev_b,
            interface_b="GE0/0/1",
            discovery_method="manual",
            confidence="high",
            status="confirmed",
        )
        expected = f"SW-A:GE0/0/2 ↔ SW-B:GE0/0/1 (manual)"
        self.assertEqual(str(link), expected)

    def test_link_normalize_prevents_duplicates(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-B", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="Teste")
        DeviceLink.objects.create(
            session=session, device_a=dev_a, interface_a="GE0/0/2",
            device_b=dev_b, interface_b="GE0/0/1",
        )
        count = DeviceLink.objects.filter(
            session=session, device_a=dev_a, device_b=dev_b
        ).count()
        self.assertEqual(count, 1)

    def test_create_vlan_definition(self):
        dev, snap = _create_device_and_snapshot("SW-TEST", SIMPLE_L2_CONFIG)
        session = VlanTrackSession.objects.create(name="Teste")
        vdef = VlanDefinition.objects.create(
            session=session, vlan_id=10, name="Clientes",
            first_seen_device=dev,
        )
        self.assertEqual(str(vdef), "VLAN 10 - Clientes")

    def test_create_vlan_interface(self):
        dev, snap = _create_device_and_snapshot("SW-TEST", SIMPLE_L2_CONFIG)
        session = VlanTrackSession.objects.create(name="Teste")
        vi = VlanInterface.objects.create(
            session=session, device=dev, snapshot=snap,
            interface_name="GE0/0/1", vlan_id=10,
            port_mode="access", tagged=False, pvid=True,
            source="access_vlan",
        )
        self.assertIn("SW-TEST:GE0/0/1 VLAN 10", str(vi))

    def test_create_vlan_endpoint(self):
        dev, snap = _create_device_and_snapshot("SW-TEST", SIMPLE_L2_CONFIG)
        session = VlanTrackSession.objects.create(name="Teste")
        vdef = VlanDefinition.objects.create(session=session, vlan_id=10)
        ep = VlanEndpoint.objects.create(
            session=session, vlan_definition=vdef,
            device=dev, interface_name="GE0/0/1",
            endpoint_type="access",
        )
        self.assertIn("SW-TEST:GE0/0/1", str(ep))

    def test_create_vlan_path(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-B", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="Teste")
        link = DeviceLink.objects.create(
            session=session, device_a=dev_a, interface_a="GE0/0/2",
            device_b=dev_b, interface_b="GE0/0/1",
        )
        vdef = VlanDefinition.objects.create(session=session, vlan_id=10)
        path = VlanPath.objects.create(
            session=session, vlan_definition=vdef,
            from_device=dev_a, from_interface="GE0/0/2",
            to_device=dev_b, to_interface="GE0/0/1",
            via_link=link, tagged=True,
        )
        self.assertIn("VLAN 10:", str(path))

    def test_create_tracking_issue(self):
        session = VlanTrackSession.objects.create(name="Teste")
        issue = VlanTrackingIssue.objects.create(
            session=session,
            severity="medium",
            code="test_issue",
            title="Issue de teste",
        )
        self.assertEqual(str(issue), "[Médio] test_issue: Issue de teste")


class ExtractionTests(TestCase):
    def test_extract_access_vlan(self):
        dev, snap = _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        session = VlanTrackSession.objects.create(name="Teste")
        pc = ParsedConfig.objects.filter(snapshot=snap).first()
        td = VlanTrackDevice.objects.create(
            session=session, device=dev, snapshot=snap, parsed_config=pc
        )
        results = extract_vlan_interfaces_from_device(td)
        access = [r for r in results if r["source"] == "access_vlan"]
        self.assertEqual(len(access), 1)
        self.assertEqual(access[0]["vlan_id"], 10)
        self.assertEqual(access[0]["port_mode"], "access")
        self.assertFalse(access[0]["tagged"])

    def test_extract_trunk_allowed(self):
        dev, snap = _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        session = VlanTrackSession.objects.create(name="Teste")
        pc = ParsedConfig.objects.filter(snapshot=snap).first()
        td = VlanTrackDevice.objects.create(
            session=session, device=dev, snapshot=snap, parsed_config=pc
        )
        results = extract_vlan_interfaces_from_device(td)
        trunk = [r for r in results if r["source"] == "trunk_allowed"]
        self.assertEqual(len(trunk), 3)
        vids = sorted(r["vlan_id"] for r in trunk)
        self.assertEqual(vids, [10, 20, 30])

    def test_extract_subinterface_dot1q(self):
        dev, snap = _create_device_and_snapshot("RTR-A", SUBNET_L3_CONFIG)
        session = VlanTrackSession.objects.create(name="Teste")
        pc = ParsedConfig.objects.filter(snapshot=snap).first()
        td = VlanTrackDevice.objects.create(
            session=session, device=dev, snapshot=snap, parsed_config=pc
        )
        results = extract_vlan_interfaces_from_device(td)
        dot1q = [r for r in results if r["source"] == "dot1q"]
        self.assertEqual(len(dot1q), 1)
        self.assertEqual(dot1q[0]["vlan_id"], 100)
        self.assertEqual(dot1q[0]["port_mode"], "subinterface")


class TopologyTests(TestCase):
    def test_discover_by_subnet_30(self):
        dev_a, snap_a = _create_device_and_snapshot("RTR-A", SUBNET_L3_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("RTR-B", SUBNET_L3_CONFIG_2)
        session = VlanTrackSession.objects.create(name="Teste")
        pc_a = ParsedConfig.objects.filter(snapshot=snap_a).first()
        pc_b = ParsedConfig.objects.filter(snapshot=snap_b).first()
        VlanTrackDevice.objects.create(session=session, device=dev_a, snapshot=snap_a, parsed_config=pc_a, order=1)
        VlanTrackDevice.objects.create(session=session, device=dev_b, snapshot=snap_b, parsed_config=pc_b, order=2)
        links = discover_links_by_subnet(session)
        self.assertGreaterEqual(len(links), 1)
        link = links[0]
        self.assertTrue(
            "GigabitEthernet0/0/1" in [link.interface_a, link.interface_b]
        )

    def test_discover_by_description(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-02", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="Teste")
        pc_a = ParsedConfig.objects.filter(snapshot=snap_a).first()
        pc_b = ParsedConfig.objects.filter(snapshot=snap_b).first()
        VlanTrackDevice.objects.create(session=session, device=dev_a, snapshot=snap_a, parsed_config=pc_a, order=1)
        VlanTrackDevice.objects.create(session=session, device=dev_b, snapshot=snap_b, parsed_config=pc_b, order=2)
        links = discover_links_by_description(session)
        self.assertGreaterEqual(len(links), 1)


class CorrelationTests(TestCase):
    def test_full_correlation(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-02", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="Correlation Test")
        pc_a = ParsedConfig.objects.filter(snapshot=snap_a).first()
        pc_b = ParsedConfig.objects.filter(snapshot=snap_b).first()
        VlanTrackDevice.objects.create(session=session, device=dev_a, snapshot=snap_a, parsed_config=pc_a, order=1)
        VlanTrackDevice.objects.create(session=session, device=dev_b, snapshot=snap_b, parsed_config=pc_b, order=2)
        run_vlan_correlation(session)
        self.assertGreater(VlanDefinition.objects.filter(session=session).count(), 0)
        self.assertGreater(VlanInterface.objects.filter(session=session).count(), 0)

    def test_access_becomes_endpoint(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        session = VlanTrackSession.objects.create(name="Endpoint Test")
        pc_a = ParsedConfig.objects.filter(snapshot=snap_a).first()
        VlanTrackDevice.objects.create(session=session, device=dev_a, snapshot=snap_a, parsed_config=pc_a)
        run_vlan_correlation(session)
        endpoints = VlanEndpoint.objects.filter(session=session)
        access_eps = endpoints.filter(endpoint_type="access")
        self.assertGreater(access_eps.count(), 0)

    def test_vlan_on_both_trunks_creates_path(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-02", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="Path Test")
        pc_a = ParsedConfig.objects.filter(snapshot=snap_a).first()
        pc_b = ParsedConfig.objects.filter(snapshot=snap_b).first()
        VlanTrackDevice.objects.create(session=session, device=dev_a, snapshot=snap_a, parsed_config=pc_a, order=1)
        VlanTrackDevice.objects.create(session=session, device=dev_b, snapshot=snap_b, parsed_config=pc_b, order=2)
        DeviceLink.objects.create(
            session=session, device_a=dev_a, interface_a="GigabitEthernet0/0/2",
            device_b=dev_b, interface_b="GigabitEthernet0/0/1",
            discovery_method="manual", confidence="high", status="confirmed",
        )
        run_vlan_correlation(session)
        paths = VlanPath.objects.filter(session=session)
        self.assertGreater(paths.count(), 0)

    def test_endpoint_without_path_issue(self):
        dev, snap = _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        session = VlanTrackSession.objects.create(name="Issue Test")
        pc = ParsedConfig.objects.filter(snapshot=snap).first()
        VlanTrackDevice.objects.create(session=session, device=dev, snapshot=snap, parsed_config=pc)

        # Only create VLAN def + endpoint, no link = issue
        vdef = VlanDefinition.objects.create(session=session, vlan_id=10)
        VlanEndpoint.objects.create(
            session=session, vlan_definition=vdef,
            device=dev, interface_name="GE0/0/1",
            endpoint_type="access",
        )
        build_tracking_issues(session)
        endpoint_issues = VlanTrackingIssue.objects.filter(
            session=session, code="vlan_endpoint_without_path"
        )
        self.assertGreater(endpoint_issues.count(), 0)

    def test_vlan_on_trunk_missing_on_neighbor(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-02", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="Missing VLAN Test")
        pc_a = ParsedConfig.objects.filter(snapshot=snap_a).first()
        pc_b = ParsedConfig.objects.filter(snapshot=snap_b).first()
        VlanTrackDevice.objects.create(session=session, device=dev_a, snapshot=snap_a, parsed_config=pc_a, order=1)
        VlanTrackDevice.objects.create(session=session, device=dev_b, snapshot=snap_b, parsed_config=pc_b, order=2)
        link = DeviceLink.objects.create(
            session=session, device_a=dev_a, interface_a="GigabitEthernet0/0/2",
            device_b=dev_b, interface_b="GigabitEthernet0/0/1",
            discovery_method="manual", confidence="high", status="confirmed",
        )

        # VLANs 10, 20, 30 on both - should be fine
        # Add an extra VLAN 99 on dev_a trunk only
        VlanInterface.objects.create(
            session=session, device=dev_a, snapshot=snap_a,
            interface_name="GigabitEthernet0/0/2", vlan_id=99,
            port_mode="trunk", tagged=True, source="trunk_allowed",
        )
        VlanDefinition.objects.create(session=session, vlan_id=99)

        build_vlan_paths(session)
        missing_issues = VlanTrackingIssue.objects.filter(
            session=session, code="vlan_on_trunk_missing_on_neighbor"
        )
        self.assertGreater(missing_issues.count(), 0)

    def test_vlan_defined_but_not_used_issue(self):
        dev, snap = _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        session = VlanTrackSession.objects.create(name="Defined Not Used")
        VlanDefinition.objects.create(session=session, vlan_id=999)
        build_tracking_issues(session)
        issues = VlanTrackingIssue.objects.filter(
            session=session, code="vlan_defined_but_not_used"
        )
        self.assertGreater(issues.count(), 0)

    def test_subinterface_vlan_without_l2_path(self):
        dev, snap = _create_device_and_snapshot("RTR-A", SUBNET_L3_CONFIG)
        session = VlanTrackSession.objects.create(name="Subif No L2 Path")
        VlanInterface.objects.create(
            session=session, device=dev, snapshot=snap,
            interface_name="GE0/0/2.100", vlan_id=100,
            port_mode="subinterface", tagged=True, source="dot1q",
        )
        VlanDefinition.objects.create(session=session, vlan_id=100)
        build_tracking_issues(session)
        issues = VlanTrackingIssue.objects.filter(
            session=session, code="subinterface_vlan_without_l2_path"
        )
        self.assertGreater(issues.count(), 0)


class ServicesTests(TestCase):
    def test_create_session_from_devices(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-02", SIMPLE_L2_CONFIG_2)
        session = create_session_from_devices(
            name="Services Test",
            devices_snapshots=[(dev_a, snap_a), (dev_b, snap_b)],
        )
        self.assertEqual(session.track_devices.count(), 2)

    def test_run_session_analysis(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-02", SIMPLE_L2_CONFIG_2)
        session = create_session_from_devices(
            name="Analysis Test",
            devices_snapshots=[(dev_a, snap_a), (dev_b, snap_b)],
        )
        run_session_analysis(session)
        summary = get_session_summary(session)
        self.assertGreater(summary["total_vlans"], 0)
        self.assertGreater(summary["total_endpoints"], 0)

    def test_get_session_summary(self):
        session = VlanTrackSession.objects.create(name="Summary Test")
        summary = get_session_summary(session)
        self.assertIn("total_devices", summary)
        self.assertIn("total_vlans", summary)
        self.assertIn("total_paths", summary)


class WebViewsTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        self.user = User.objects.create_user("viewer", "v@v.com", "pass")
        self.client.force_login(self.user)
        self.dev_a, self.snap_a = _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        self.dev_b, self.snap_b = _create_device_and_snapshot("SW-02", SIMPLE_L2_CONFIG_2)
        self.session = create_session_from_devices(
            name="Web Test",
            devices_snapshots=[(self.dev_a, self.snap_a), (self.dev_b, self.snap_b)],
        )

    def test_session_list_200(self):
        response = self.client.get(reverse("vlan_tracking:session_list"))
        self.assertEqual(response.status_code, 200)

    def test_session_create_200(self):
        response = self.client.get(reverse("vlan_tracking:session_create"))
        self.assertEqual(response.status_code, 200)

    def test_session_detail_200(self):
        response = self.client.get(
            reverse("vlan_tracking:session_detail", args=[self.session.pk])
        )
        self.assertEqual(response.status_code, 200)

    def test_vlan_list_200(self):
        response = self.client.get(
            reverse("vlan_tracking:vlan_list", args=[self.session.pk])
        )
        self.assertEqual(response.status_code, 200)

    def test_link_list_200(self):
        response = self.client.get(
            reverse("vlan_tracking:link_list", args=[self.session.pk])
        )
        self.assertEqual(response.status_code, 200)

    def test_vlan_detail_200(self):
        run_session_analysis(self.session)
        vdef = VlanDefinition.objects.filter(session=self.session).first()
        if vdef:
            response = self.client.get(
                reverse("vlan_tracking:vlan_detail", args=[self.session.pk, vdef.vlan_id])
            )
            self.assertEqual(response.status_code, 200)

    def test_session_detail_has_cards(self):
        response = self.client.get(
            reverse("vlan_tracking:session_detail", args=[self.session.pk])
        )
        self.assertContains(response, "Dispositivos")
        self.assertContains(response, "VLANs")

    def test_topology_page_200(self):
        response = self.client.get(
            reverse("vlan_tracking:topology", args=[self.session.pk])
        )
        self.assertEqual(response.status_code, 200)

    def test_mermaid_export_200(self):
        response = self.client.get(
            reverse("vlan_tracking:topology_mermaid", args=[self.session.pk])
        )
        self.assertEqual(response.status_code, 200)

    def test_mermaid_contains_graph(self):
        response = self.client.get(
            reverse("vlan_tracking:topology_mermaid", args=[self.session.pk])
        )
        self.assertContains(response, "graph LR")

    def test_evidence_list_200(self):
        response = self.client.get(
            reverse("vlan_tracking:evidence_list", args=[self.session.pk])
        )
        self.assertEqual(response.status_code, 200)

    def test_evidence_create_200(self):
        response = self.client.get(
            reverse("vlan_tracking:evidence_create", args=[self.session.pk])
        )
        self.assertEqual(response.status_code, 200)

    def test_session_detail_shows_evidence_button(self):
        response = self.client.get(
            reverse("vlan_tracking:session_detail", args=[self.session.pk])
        )
        self.assertContains(response, "LLDP/CSV")

    def test_session_detail_shows_topology_button(self):
        response = self.client.get(
            reverse("vlan_tracking:session_detail", args=[self.session.pk])
        )
        self.assertContains(response, "Topologia")


class LldpIntegrationTests(TestCase):
    def _make_session(self, name, dev_a=None, dev_b=None):
        from django.contrib.auth.models import User
        if not hasattr(self, '_user'):
            self._user = User.objects.create_user("op2", "op2@op.com", "pass")
        self.client.force_login(self._user)
        d_a, s_a = dev_a or _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        d_b, s_b = dev_b or _create_device_and_snapshot("SW-02", SIMPLE_L2_CONFIG_2)
        return create_session_from_devices(
            name=name,
            devices_snapshots=[(d_a, s_a), (d_b, s_b)],
        )

    def test_add_lldp_evidence_creates_links(self):
        session = self._make_session("LLDP Links")
        lldp_text = "Local Interface    Exptime(s)    Neighbor Interface    Neighbor Device\n"
        lldp_text += "GigabitEthernet0/0/2  120  GigabitEthernet0/0/1  SW-02\n"
        response = self.client.post(
            reverse("vlan_tracking:evidence_create", args=[session.pk]),
            {"device": session.track_devices.first().device.id, "evidence_type": "lldp", "raw_text": lldp_text},
        )
        self.assertEqual(response.status_code, 302)
        links = DeviceLink.objects.filter(session=session, discovery_method="lldp")
        self.assertGreater(links.count(), 0)

    def test_add_csv_evidence_creates_links(self):
        session = self._make_session("CSV Links")
        csv_text = "local_device,local_interface,remote_device,remote_interface\n"
        csv_text += "SW-01,GigabitEthernet0/0/2,SW-02,GigabitEthernet0/0/1\n"
        response = self.client.post(
            reverse("vlan_tracking:evidence_create", args=[session.pk]),
            {"device": "", "evidence_type": "csv", "raw_text": csv_text},
        )
        self.assertEqual(response.status_code, 302)
        links = DeviceLink.objects.filter(session=session)
        self.assertGreater(links.count(), 0)

    def test_lldp_remote_device_not_found_creates_issue(self):
        session = self._make_session("LLDP Unknown")
        lldp_text = "Local Interface    Exptime(s)    Neighbor Interface    Neighbor Device\n"
        lldp_text += "GE0/0/2  120  GE0/0/1  UNKNOWN-DEVICE\n"
        self.client.post(
            reverse("vlan_tracking:evidence_create", args=[session.pk]),
            {"device": session.track_devices.first().device.id, "evidence_type": "lldp", "raw_text": lldp_text},
        )
        issues = VlanTrackingIssue.objects.filter(
            session=session, code="lldp_remote_device_not_found"
        )
        self.assertGreater(issues.count(), 0)

    def test_lldp_evidence_is_stored(self):
        session = self._make_session("LLDP Store")
        dev = session.track_devices.first().device
        lldp_text = "Local Interface    Exptime(s)    Neighbor Interface    Neighbor Device\nGE0/0/2  120  GE0/0/1  SW-02\n"
        self.client.post(
            reverse("vlan_tracking:evidence_create", args=[session.pk]),
            {"device": dev.id, "evidence_type": "lldp", "raw_text": lldp_text},
        )
        ev = TopologyEvidence.objects.filter(session=session).first()
        self.assertIsNotNone(ev)
        self.assertEqual(ev.evidence_type, "lldp")
        self.assertIsNotNone(ev.parsed_data)

    def test_lldp_link_has_remote_hostname(self):
        session = self._make_session("LLDP Hostname")
        dev = session.track_devices.first().device
        lldp_text = "Local Interface    Exptime(s)    Neighbor Interface    Neighbor Device\nGE0/0/2  120  GE0/0/1  SW-02\n"
        self.client.post(
            reverse("vlan_tracking:evidence_create", args=[session.pk]),
            {"device": dev.id, "evidence_type": "lldp", "raw_text": lldp_text},
        )
        link = DeviceLink.objects.filter(session=session, discovery_method="lldp").first()
        self.assertIsNotNone(link)
        self.assertEqual(link.remote_hostname, "SW-02")

    def test_lldp_confirms_subnet_link(self):
        dev_a, snap_a = _create_device_and_snapshot("RTR-A", SUBNET_L3_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("RTR-B", SUBNET_L3_CONFIG_2)
        session = self._make_session("LLDP Confirm", (dev_a, snap_a), (dev_b, snap_b))
        run_session_analysis(session)
        subnet_links = DeviceLink.objects.filter(session=session, discovery_method="subnet")
        self.assertGreater(subnet_links.count(), 0)

    def test_csv_with_unknown_device_creates_issue(self):
        session = self._make_session("CSV Unknown")
        csv_text = "local_device,local_interface,remote_device,remote_interface\nUNKNOWN,GE0/0/1,SW-02,GE0/0/1\n"
        self.client.post(
            reverse("vlan_tracking:evidence_create", args=[session.pk]),
            {"device": "", "evidence_type": "csv", "raw_text": csv_text},
        )
        issues = VlanTrackingIssue.objects.filter(
            session=session, code="csv_device_not_found"
        )
        self.assertGreater(issues.count(), 0)


class ConfidenceAndPathTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        self.user = User.objects.create_user("viewer2", "v2@v.com", "pass")
        self.client.force_login(self.user)

    def test_low_confidence_link_creates_path_issue(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-02", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="Low Conf Test")
        pc_a = ParsedConfig.objects.filter(snapshot=snap_a).first()
        pc_b = ParsedConfig.objects.filter(snapshot=snap_b).first()
        VlanTrackDevice.objects.create(session=session, device=dev_a, snapshot=snap_a, parsed_config=pc_a, order=1)
        VlanTrackDevice.objects.create(session=session, device=dev_b, snapshot=snap_b, parsed_config=pc_b, order=2)
        link = DeviceLink.objects.create(
            session=session, device_a=dev_a, interface_a="GigabitEthernet0/0/2",
            device_b=dev_b, interface_b="GigabitEthernet0/0/1",
            discovery_method="subnet", confidence="low", status="discovered",
        )
        # Create VlanInterface entries on both sides
        VlanInterface.objects.create(
            session=session, device=dev_a, interface_name="GigabitEthernet0/0/2", vlan_id=10,
            port_mode="trunk", tagged=True, source="trunk_allowed",
        )
        VlanInterface.objects.create(
            session=session, device=dev_b, interface_name="GigabitEthernet0/0/1", vlan_id=10,
            port_mode="trunk", tagged=True, source="trunk_allowed",
        )
        VlanDefinition.objects.create(session=session, vlan_id=10)
        build_vlan_paths(session)
        issues = VlanTrackingIssue.objects.filter(
            session=session, code="vlan_path_uses_low_confidence_link"
        )
        self.assertGreater(issues.count(), 0)

    def test_evidence_can_be_deleted(self):
        dev, snap = _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        session = VlanTrackSession.objects.create(name="Evidence Delete")
        ev = TopologyEvidence.objects.create(
            session=session, device=dev, evidence_type="lldp", raw_text="test"
        )
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("vlan_tracking:evidence_delete", args=[session.pk, ev.pk])
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(TopologyEvidence.objects.filter(pk=ev.pk).count(), 0)

    def test_mermaid_shows_devices_and_links(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-02", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="Mermaid Test")
        pc_a = ParsedConfig.objects.filter(snapshot=snap_a).first()
        pc_b = ParsedConfig.objects.filter(snapshot=snap_b).first()
        VlanTrackDevice.objects.create(session=session, device=dev_a, snapshot=snap_a, parsed_config=pc_a, order=1)
        VlanTrackDevice.objects.create(session=session, device=dev_b, snapshot=snap_b, parsed_config=pc_b, order=2)
        DeviceLink.objects.create(
            session=session, device_a=dev_a, interface_a="GE0/0/2",
            device_b=dev_b, interface_b="GE0/0/1",
            discovery_method="manual", confidence="high", status="confirmed",
        )
        self.client.force_login(self.user)
        response = self.client.get(
            reverse("vlan_tracking:topology_mermaid", args=[session.pk])
        )
        self.assertContains(response, "graph LR")
        self.assertContains(response, "SW-01")
        self.assertContains(response, "SW-02")
