from django.test import TestCase
from django.urls import reverse

from apps.analysis.models import ParsedConfig
from apps.core.tests import *
from apps.devices.models import Device

from ..models import DeviceLink, VlanDefinition, VlanInterface, VlanPath, VlanTrackDevice, VlanTrackSession
from ..presentation import (
    format_confidence_label,
    format_discovery_method_label,
    get_link_display_data,
    get_link_vlan_ids,
    get_topology_filter_options,
    get_vlan_path_display_data,
)
from ..services import create_session_from_devices, run_session_analysis
from ..tests.test_vlan_tracking import SIMPLE_L2_CONFIG, SIMPLE_L2_CONFIG_2, _create_device_and_snapshot


class PresentationHelpersTests(TestCase):
    def test_confidence_label_high(self):
        self.assertEqual(format_confidence_label("high"), "Alta")

    def test_confidence_label_medium(self):
        self.assertEqual(format_confidence_label("medium"), "Média")

    def test_confidence_label_low(self):
        self.assertEqual(format_confidence_label("low"), "Baixa")

    def test_confidence_label_unknown(self):
        self.assertEqual(format_confidence_label("unknown"), "unknown")

    def test_method_label_manual(self):
        self.assertEqual(format_discovery_method_label("manual"), "Manual")

    def test_method_label_lldp(self):
        self.assertEqual(format_discovery_method_label("lldp"), "LLDP")

    def test_method_label_csv(self):
        self.assertEqual(format_discovery_method_label("csv"), "CSV")

    def test_method_label_subnet(self):
        self.assertEqual(format_discovery_method_label("subnet"), "Sub-rede")

    def test_method_label_description(self):
        self.assertEqual(format_discovery_method_label("description"), "Descrição")

    def test_method_label_unknown(self):
        self.assertEqual(format_discovery_method_label("unknown"), "unknown")


class GetLinkVlanIdsTests(TestCase):
    def test_get_link_vlan_ids_returns_ids(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-02", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="VLAN IDs Test")
        pc_a = ParsedConfig.objects.filter(snapshot=snap_a).first()
        pc_b = ParsedConfig.objects.filter(snapshot=snap_b).first()
        VlanTrackDevice.objects.create(session=session, device=dev_a, snapshot=snap_a, parsed_config=pc_a, order=1)
        VlanTrackDevice.objects.create(session=session, device=dev_b, snapshot=snap_b, parsed_config=pc_b, order=2)
        link = DeviceLink.objects.create(
            session=session, device_a=dev_a, interface_a="GE0/0/2",
            device_b=dev_b, interface_b="GE0/0/1",
        )
        vdef = VlanDefinition.objects.create(session=session, vlan_id=10)
        VlanPath.objects.create(
            session=session, vlan_definition=vdef,
            from_device=dev_a, from_interface="GE0/0/2",
            to_device=dev_b, to_interface="GE0/0/1",
            via_link=link,
        )
        ids = get_link_vlan_ids(link)
        self.assertIn(10, ids)

    def test_get_link_vlan_ids_no_paths(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-01", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-02", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="No Paths")
        link = DeviceLink.objects.create(
            session=session, device_a=dev_a, interface_a="GE0/0/2",
            device_b=dev_b, interface_b="GE0/0/1",
        )
        ids = get_link_vlan_ids(link)
        self.assertEqual(ids, [])


class GetLinkDisplayDataTests(TestCase):
    def setUp(self):
        self.dev_a, self.snap_a = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG)
        self.dev_b, self.snap_b = _create_device_and_snapshot("SW-B", SIMPLE_L2_CONFIG_2)
        self.session = VlanTrackSession.objects.create(name="Display Data")
        self.link = DeviceLink.objects.create(
            session=self.session, device_a=self.dev_a, interface_a="GE0/0/2",
            device_b=self.dev_b, interface_b="GE0/0/1",
            discovery_method="lldp", confidence="high",
        )
        vdef = VlanDefinition.objects.create(session=self.session, vlan_id=10)
        VlanPath.objects.create(
            session=self.session, vlan_definition=vdef,
            from_device=self.dev_a, from_interface="GE0/0/2",
            to_device=self.dev_b, to_interface="GE0/0/1",
            via_link=self.link,
        )

    def test_get_link_display_data_returns_vlans(self):
        data = get_link_display_data(self.session)
        self.assertGreater(len(data), 0)
        self.assertIn(10, data[0]["vlan_ids"])

    def test_get_link_display_data_has_labels(self):
        data = get_link_display_data(self.session)
        item = data[0]
        self.assertEqual(item["method_label"], "LLDP")
        self.assertEqual(item["confidence_label"], "Alta")

    def test_filter_by_method(self):
        data = get_link_display_data(self.session, {"method": "lldp"})
        self.assertGreater(len(data), 0)
        data2 = get_link_display_data(self.session, {"method": "subnet"})
        self.assertEqual(len(data2), 0)

    def test_filter_by_confidence(self):
        data = get_link_display_data(self.session, {"confidence": "high"})
        self.assertGreater(len(data), 0)
        data2 = get_link_display_data(self.session, {"confidence": "low"})
        self.assertEqual(len(data2), 0)

    def test_filter_by_device(self):
        data = get_link_display_data(self.session, {"device": "SW-A"})
        self.assertGreater(len(data), 0)

    def test_filter_by_vlan(self):
        data = get_link_display_data(self.session, {"vlan": "10"})
        self.assertGreater(len(data), 0)
        data2 = get_link_display_data(self.session, {"vlan": "999"})
        self.assertEqual(len(data2), 0)


class VlanPathDisplayDataTests(TestCase):
    def setUp(self):
        self.dev_a, self.snap_a = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG)
        self.dev_b, self.snap_b = _create_device_and_snapshot("SW-B", SIMPLE_L2_CONFIG_2)
        self.session = VlanTrackSession.objects.create(name="Vlan Path Display")
        self.link = DeviceLink.objects.create(
            session=self.session, device_a=self.dev_a, interface_a="GE0/0/2",
            device_b=self.dev_b, interface_b="GE0/0/1",
            discovery_method="lldp", confidence="high",
        )
        self.vdef = VlanDefinition.objects.create(session=self.session, vlan_id=10)
        VlanPath.objects.create(
            session=self.session, vlan_definition=self.vdef,
            from_device=self.dev_a, from_interface="GE0/0/2",
            to_device=self.dev_b, to_interface="GE0/0/1",
            via_link=self.link,
        )

    def test_get_vlan_path_display_returns_data(self):
        data = get_vlan_path_display_data(self.session, 10)
        self.assertIsNotNone(data)
        self.assertEqual(data["definition"].vlan_id, 10)

    def test_get_vlan_path_display_has_paths(self):
        data = get_vlan_path_display_data(self.session, 10)
        self.assertGreater(data["path_count"], 0)

    def test_get_vlan_path_display_has_method_and_confidence(self):
        data = get_vlan_path_display_data(self.session, 10)
        path = data["paths"][0]
        self.assertEqual(path["method"], "lldp")
        self.assertEqual(path["confidence"], "high")

    def test_get_vlan_path_display_nonexistent_vlan(self):
        data = get_vlan_path_display_data(self.session, 999)
        self.assertIsNone(data)

    def test_get_vlan_path_display_low_confidence_flag(self):
        link2 = DeviceLink.objects.create(
            session=self.session, device_a=self.dev_a, interface_a="GE0/0/1",
            device_b=self.dev_b, interface_b="GE0/0/2",
            discovery_method="subnet", confidence="low",
        )
        VlanPath.objects.create(
            session=self.session, vlan_definition=self.vdef,
            from_device=self.dev_a, from_interface="GE0/0/1",
            to_device=self.dev_b, to_interface="GE0/0/2",
            via_link=link2,
        )
        data = get_vlan_path_display_data(self.session, 10)
        self.assertTrue(data["has_low_confidence_path"])

    def test_filter_options_include_methods(self):
        options = get_topology_filter_options(self.session)
        self.assertIn("lldp", options["methods"])

    def test_filter_options_include_devices(self):
        from ..models import VlanTrackDevice
        VlanTrackDevice.objects.create(
            session=self.session, device=self.dev_a, snapshot=self.snap_a, order=1
        )
        options = get_topology_filter_options(self.session)
        self.assertIn("SW-A", options["devices"])


class TopologyWebFiltersTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        self.user = User.objects.create_user("topo", "topo@topo.com", "pass")
        self.client.force_login(self.user)
        self.dev_a, self.snap_a = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG)
        self.dev_b, self.snap_b = _create_device_and_snapshot("SW-B", SIMPLE_L2_CONFIG_2)
        self.session = VlanTrackSession.objects.create(name="Topo Filter")

    def test_topology_shows_devices(self):
        response = self.client.get(reverse("vlan_tracking:topology", args=[self.session.pk]))
        self.assertEqual(response.status_code, 200)

    def test_topology_shows_links(self):
        DeviceLink.objects.create(
            session=self.session, device_a=self.dev_a, interface_a="GE0/0/2",
            device_b=self.dev_b, interface_b="GE0/0/1",
        )
        response = self.client.get(reverse("vlan_tracking:topology", args=[self.session.pk]))
        self.assertContains(response, "SW-A")
        self.assertContains(response, "SW-B")

    def test_topology_filter_by_method(self):
        DeviceLink.objects.create(
            session=self.session, device_a=self.dev_a, interface_a="GE0/0/2",
            device_b=self.dev_b, interface_b="GE0/0/1",
            discovery_method="lldp",
        )
        response = self.client.get(
            reverse("vlan_tracking:topology", args=[self.session.pk]) + "?method=lldp"
        )
        self.assertEqual(response.status_code, 200)

    def test_topology_filter_by_vlan(self):
        link = DeviceLink.objects.create(
            session=self.session, device_a=self.dev_a, interface_a="GE0/0/2",
            device_b=self.dev_b, interface_b="GE0/0/1",
        )
        vdef = VlanDefinition.objects.create(session=self.session, vlan_id=100)
        VlanPath.objects.create(
            session=self.session, vlan_definition=vdef,
            from_device=self.dev_a, from_interface="GE0/0/2",
            to_device=self.dev_b, to_interface="GE0/0/1",
            via_link=link,
        )
        response = self.client.get(
            reverse("vlan_tracking:topology", args=[self.session.pk]) + "?vlan=100"
        )
        self.assertContains(response, "SW-A")
        response2 = self.client.get(
            reverse("vlan_tracking:topology", args=[self.session.pk]) + "?vlan=999"
        )
        self.assertNotContains(response2, "SW-A")

    def test_topology_shows_mermaid_block(self):
        DeviceLink.objects.create(
            session=self.session, device_a=self.dev_a, interface_a="GE0/0/2",
            device_b=self.dev_b, interface_b="GE0/0/1",
        )
        response = self.client.get(reverse("vlan_tracking:topology", args=[self.session.pk]))
        self.assertContains(response, "graph LR")

    def test_vlan_detail_shows_path_info(self):
        link = DeviceLink.objects.create(
            session=self.session, device_a=self.dev_a, interface_a="GE0/0/2",
            device_b=self.dev_b, interface_b="GE0/0/1",
            discovery_method="lldp", confidence="high",
        )
        pc_a = ParsedConfig.objects.filter(snapshot=self.snap_a).first()
        pc_b = ParsedConfig.objects.filter(snapshot=self.snap_b).first()
        VlanTrackDevice.objects.create(session=self.session, device=self.dev_a, snapshot=self.snap_a, parsed_config=pc_a, order=1)
        VlanTrackDevice.objects.create(session=self.session, device=self.dev_b, snapshot=self.snap_b, parsed_config=pc_b, order=2)
        vdef = VlanDefinition.objects.create(session=self.session, vlan_id=10)
        VlanPath.objects.create(
            session=self.session, vlan_definition=vdef,
            from_device=self.dev_a, from_interface="GE0/0/2",
            to_device=self.dev_b, to_interface="GE0/0/1",
            via_link=link,
        )
        VlanInterface.objects.create(
            session=self.session, device=self.dev_a, interface_name="GE0/0/1", vlan_id=10,
            port_mode="access", tagged=False, pvid=True, source="access_vlan",
        )
        response = self.client.get(
            reverse("vlan_tracking:vlan_detail", args=[self.session.pk, 10])
        )
        self.assertContains(response, "10")
        self.assertContains(response, "SW-A")

    def test_mermaid_export_with_vlan_filter(self):
        link = DeviceLink.objects.create(
            session=self.session, device_a=self.dev_a, interface_a="GE0/0/2",
            device_b=self.dev_b, interface_b="GE0/0/1",
        )
        vdef = VlanDefinition.objects.create(session=self.session, vlan_id=100)
        VlanPath.objects.create(
            session=self.session, vlan_definition=vdef,
            from_device=self.dev_a, from_interface="GE0/0/2",
            to_device=self.dev_b, to_interface="GE0/0/1",
            via_link=link,
        )
        response = self.client.get(
            reverse("vlan_tracking:topology_mermaid", args=[self.session.pk]) + "?vlan=100"
        )
        self.assertContains(response, "graph LR")
        self.assertContains(response, "SW-A")
        response2 = self.client.get(
            reverse("vlan_tracking:topology_mermaid", args=[self.session.pk]) + "?vlan=999"
        )
        self.assertNotContains(response2, "SW-A")

    def test_session_detail_shows_topology_button(self):
        response = self.client.get(
            reverse("vlan_tracking:session_detail", args=[self.session.pk])
        )
        self.assertContains(response, "Topologia")
        self.assertContains(response, "Mermaid")

    def test_link_list_shows_filters(self):
        response = self.client.get(
            reverse("vlan_tracking:link_list", args=[self.session.pk])
        )
        self.assertEqual(response.status_code, 200)
