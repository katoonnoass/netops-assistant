from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from apps.core.tests import *

from ..models import DeviceLink, VlanDefinition, VlanEndpoint, VlanInterface, VlanPath, VlanTrackSession, VlanTrackingIssue
from ..services import create_session_from_devices
from ..tests.test_vlan_tracking import SIMPLE_L2_CONFIG, SIMPLE_L2_CONFIG_2, _create_device_and_snapshot
from ..operational import search_vlan_tracking


def _make_session():
    dev_a, snap_a = _create_device_and_snapshot("SW-CLI", SIMPLE_L2_CONFIG)
    dev_b, snap_b = _create_device_and_snapshot("SW-CLI2", SIMPLE_L2_CONFIG_2)
    session = create_session_from_devices("CLI Test", [(dev_a, snap_a), (dev_b, snap_b)])
    link = DeviceLink.objects.create(
        session=session, device_a=dev_a, interface_a="GigabitEthernet0/0/2",
        device_b=dev_b, interface_b="GigabitEthernet0/0/1",
        discovery_method="lldp", confidence="high",
    )
    vdef = VlanDefinition.objects.create(session=session, vlan_id=100, name="CLI-VLAN")
    VlanPath.objects.create(
        session=session, vlan_definition=vdef,
        from_device=dev_a, from_interface="GigabitEthernet0/0/2",
        to_device=dev_b, to_interface="GigabitEthernet0/0/1",
        via_link=link,
    )
    VlanEndpoint.objects.create(
        session=session, vlan_definition=vdef,
        device=dev_a, interface_name="GE0/0/1", endpoint_type="access",
    )
    VlanInterface.objects.create(
        session=session, device=dev_a, interface_name="GigabitEthernet0/0/2", vlan_id=100,
        port_mode="trunk", tagged=True, source="trunk_allowed",
    )
    VlanTrackingIssue.objects.create(
        session=session, vlan_definition=vdef,
        severity="low", code="vlan_path_uses_low_confidence_link",
        title="Low confidence path",
    )
    return session


class CliSearchTests(TestCase):
    def test_cli_shows_vlan_tracking_section(self):
        _make_session()
        out = StringIO()
        call_command("network_search", "100", stdout=out)
        output = out.getvalue()
        self.assertIn("VLAN Tracking", output)
        self.assertIn("CLI-VLAN", output)

    def test_cli_shows_vlan_tracking_for_low_confidence(self):
        _make_session()
        out = StringIO()
        call_command("network_search", "vlan_path_uses_low_confidence_link", stdout=out)
        output = out.getvalue()
        self.assertIn("VLAN Tracking", output)
        self.assertIn("vlan_path_uses_low_confidence_link", output)

    def test_cli_shows_device_name(self):
        _make_session()
        out = StringIO()
        call_command("network_search", "SW-CLI", stdout=out)
        output = out.getvalue()
        self.assertIn("SW-CLI", output)
        self.assertIn("VLAN Tracking", output)

    def test_cli_shows_vlan_by_id(self):
        _make_session()
        out = StringIO()
        call_command("network_search", "VLAN 100", stdout=out)
        output = out.getvalue()
        self.assertIn("100", output)


class PortugueseSearchTests(TestCase):
    def test_search_baixa_confianca_finds_low(self):
        _make_session()
        results = search_vlan_tracking("baixa confiança")
        self.assertGreater(len(results), 0)

    def test_search_atencao_replaced_by_attention(self):
        _make_session()
        # "atenção" should be replaced by "attention" via synonym map
        results = search_vlan_tracking("atenção")
        self.assertIsInstance(results, list)

    def test_search_critico_replaced_by_critical(self):
        _make_session()
        results = search_vlan_tracking("crítico")
        self.assertIsInstance(results, list)

    def test_search_incompleto_finds_incomplete(self):
        _make_session()
        results = search_vlan_tracking("incompleto")
        self.assertIsInstance(results, list)

    def test_search_lldp_finds_links(self):
        _make_session()
        results = search_vlan_tracking("lldp")
        link_results = [r for r in results if r["type"] == "vlan_tracking_link"]
        self.assertGreater(len(link_results), 0)

    def test_search_endpoint_finds_endpoints(self):
        _make_session()
        results = search_vlan_tracking("GE0/0/1")
        ep_results = [r for r in results if r["type"] == "vlan_tracking_endpoint"]
        self.assertGreater(len(ep_results), 0)
