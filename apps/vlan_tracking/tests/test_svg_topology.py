from django.test import TestCase
from django.urls import reverse

from apps.analysis.models import ParsedConfig
from apps.core.tests import *
from apps.devices.models import Device

from ..models import (
    DeviceLink,
    VlanDefinition,
    VlanEndpoint,
    VlanInterface,
    VlanPath,
    VlanTrackDevice,
    VlanTrackSession,
)
from ..services import create_session_from_devices
from ..svg_topology import build_svg_topology, calculate_node_positions
from ..tests.test_vlan_tracking import SIMPLE_L2_CONFIG, SIMPLE_L2_CONFIG_2, _create_device_and_snapshot


class SvgHelpersTests(TestCase):
    def test_calculate_positions_empty(self):
        session = VlanTrackSession.objects.create(name="Empty")
        positions, devices = calculate_node_positions(session, [])
        self.assertEqual(positions, {})
        self.assertEqual(devices, [])

    def test_build_svg_contains_svg_tag(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-B", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="SVG Test")
        DeviceLink.objects.create(
            session=session, device_a=dev_a, interface_a="GE0/0/2",
            device_b=dev_b, interface_b="GE0/0/1",
            discovery_method="lldp", confidence="high",
        )
        result = build_svg_topology(session)
        self.assertIn("<svg", result["svg"])
        self.assertIn("</svg>", result["svg"])

    def test_build_svg_contains_device_names(self):
        dev_a, snap_a = _create_device_and_snapshot("SVG-SW-A", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SVG-SW-B", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="SVG Names")
        DeviceLink.objects.create(
            session=session, device_a=dev_a, interface_a="GE0/0/2",
            device_b=dev_b, interface_b="GE0/0/1",
        )
        result = build_svg_topology(session)
        self.assertIn("SVG-SW-A", result["svg"])
        self.assertIn("SVG-SW-B", result["svg"])

    def test_build_svg_contains_interface_labels(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-B", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="SVG Ifaces")
        DeviceLink.objects.create(
            session=session, device_a=dev_a, interface_a="GE0/0/2",
            device_b=dev_b, interface_b="GE0/0/1",
        )
        result = build_svg_topology(session)
        self.assertIn("GE0/0/2", result["svg"])
        self.assertIn("GE0/0/1", result["svg"])

    def test_build_svg_contains_method_and_confidence(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-B", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="SVG Method")
        DeviceLink.objects.create(
            session=session, device_a=dev_a, interface_a="GE0/0/2",
            device_b=dev_b, interface_b="GE0/0/1",
            discovery_method="lldp", confidence="high",
        )
        result = build_svg_topology(session)
        self.assertIn("LLDP", result["svg"])
        self.assertIn("Alta", result["svg"])

    def test_build_svg_with_vlan_filter(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-B", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="SVG VLAN")
        link = DeviceLink.objects.create(
            session=session, device_a=dev_a, interface_a="GE0/0/2",
            device_b=dev_b, interface_b="GE0/0/1",
        )
        vdef = VlanDefinition.objects.create(session=session, vlan_id=100)
        VlanPath.objects.create(
            session=session, vlan_definition=vdef,
            from_device=dev_a, from_interface="GE0/0/2",
            to_device=dev_b, to_interface="GE0/0/1",
            via_link=link,
        )
        result = build_svg_topology(session, vlan_id=100)
        self.assertIn("VLANs: 100", result["svg"])
        result2 = build_svg_topology(session, vlan_id=999)
        self.assertNotIn("SW-A", result2["svg"])


class SvgSanitizeTests(TestCase):
    def test_svg_escapes_special_chars(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-01<script>", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-02", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="SVG Sanitize")
        DeviceLink.objects.create(
            session=session, device_a=dev_a, interface_a="GE0/0/2 & test",
            device_b=dev_b, interface_b="GE0/0/1",
        )
        result = build_svg_topology(session)
        self.assertNotIn("<script>", result["svg"])
        self.assertIn("&lt;script&gt;", result["svg"])
        self.assertIn("&amp; test", result["svg"])

    def test_session_name_sanitized(self):
        session = VlanTrackSession.objects.create(name='<script>alert("xss")</script>')
        result = build_svg_topology(session)
        self.assertNotIn("<script>", result["svg"])
        self.assertIn("&lt;script&gt;", result["svg"])


class SvgEndpointTests(TestCase):
    def test_vlan_svg_shows_endpoint_marker(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-B", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="SVG Endpoint")
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
        VlanEndpoint.objects.create(
            session=session, vlan_definition=vdef,
            device=dev_a, interface_name="GE0/0/1",
            endpoint_type="access",
        )
        result = build_svg_topology(session, vlan_id=10)
        self.assertIn("●", result["svg"])

    def test_vlan_svg_shows_l3_endpoint(self):
        dev_a, snap_a = _create_device_and_snapshot("RTR-A", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("RTR-B", SIMPLE_L2_CONFIG_2)
        session = VlanTrackSession.objects.create(name="SVG L3")
        DeviceLink.objects.create(
            session=session, device_a=dev_a, interface_a="GE0/0/1",
            device_b=dev_b, interface_b="GE0/0/1",
        )
        vdef = VlanDefinition.objects.create(session=session, vlan_id=100)
        VlanEndpoint.objects.create(
            session=session, vlan_definition=vdef,
            device=dev_a, interface_name="GE0/0/2.100",
            endpoint_type="subinterface_l3",
        )
        result = build_svg_topology(session, vlan_id=100)
        self.assertIn("■", result["svg"])


class SvgWebViewsTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        self.user = User.objects.create_user("svguser", "svg@svg.com", "pass")
        self.client.force_login(self.user)
        self.dev_a, self.snap_a = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG)
        self.dev_b, self.snap_b = _create_device_and_snapshot("SW-B", SIMPLE_L2_CONFIG_2)
        self.session = VlanTrackSession.objects.create(name="SVG Web")
        DeviceLink.objects.create(
            session=self.session, device_a=self.dev_a, interface_a="GE0/0/2",
            device_b=self.dev_b, interface_b="GE0/0/1",
        )

    def test_svg_page_200(self):
        response = self.client.get(
            reverse("vlan_tracking:topology_svg", args=[self.session.pk])
        )
        self.assertEqual(response.status_code, 200)

    def test_svg_page_contains_svg(self):
        response = self.client.get(
            reverse("vlan_tracking:topology_svg", args=[self.session.pk])
        )
        self.assertContains(response, "<svg")

    def test_svg_download_returns_svg(self):
        response = self.client.get(
            reverse("vlan_tracking:topology_svg_download", args=[self.session.pk])
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "image/svg+xml; charset=utf-8")

    def test_svg_download_with_vlan_filter(self):
        link = DeviceLink.objects.first()
        vdef = VlanDefinition.objects.create(session=self.session, vlan_id=50)
        VlanPath.objects.create(
            session=self.session, vlan_definition=vdef,
            from_device=self.dev_a, from_interface="GE0/0/2",
            to_device=self.dev_b, to_interface="GE0/0/1",
            via_link=link,
        )
        response = self.client.get(
            reverse("vlan_tracking:topology_svg_download", args=[self.session.pk]) + "?vlan=50"
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("VLANs: 50", response.content.decode())

    def test_svg_page_shows_stats(self):
        response = self.client.get(
            reverse("vlan_tracking:topology_svg", args=[self.session.pk])
        )
        self.assertContains(response, "Dispositivos")
        self.assertContains(response, "Enlaces")

    def test_session_detail_has_svg_button(self):
        response = self.client.get(
            reverse("vlan_tracking:session_detail", args=[self.session.pk])
        )
        self.assertContains(response, "Grafo SVG")

    def test_vlan_detail_has_svg_link(self):
        vdef = VlanDefinition.objects.create(session=self.session, vlan_id=10)
        VlanInterface.objects.create(
            session=self.session, device=self.dev_a, interface_name="GE0/0/1",
            vlan_id=10, port_mode="access", source="access_vlan",
        )
        response = self.client.get(
            reverse("vlan_tracking:vlan_detail", args=[self.session.pk, 10])
        )
        self.assertContains(response, "Ver grafo desta VLAN")
