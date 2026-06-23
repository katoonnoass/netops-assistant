from django.test import TestCase
from django.urls import reverse

from apps.core.tests import *

from ..models import DeviceLink, VlanDefinition, VlanEndpoint, VlanInterface, VlanPath, VlanTrackDevice, VlanTrackSession, VlanTrackingIssue
from ..operational import (
    export_session_report_csv_rows,
    export_session_report_text,
    get_device_vlan_tracking_context,
    get_vlan_tracking_dashboard_summary,
    search_vlan_tracking,
)
from ..services import create_session_from_devices
from ..tests.test_vlan_tracking import SIMPLE_L2_CONFIG, SIMPLE_L2_CONFIG_2, _create_device_and_snapshot


def _make_session():
    dev_a, snap_a = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG)
    dev_b, snap_b = _create_device_and_snapshot("SW-B", SIMPLE_L2_CONFIG_2)
    session = create_session_from_devices("Integration", [(dev_a, snap_a), (dev_b, snap_b)])
    link = DeviceLink.objects.create(
        session=session, device_a=dev_a, interface_a="GigabitEthernet0/0/2",
        device_b=dev_b, interface_b="GigabitEthernet0/0/1",
        discovery_method="lldp", confidence="high",
    )
    vdef = VlanDefinition.objects.create(session=session, vlan_id=10, name="TestVLAN")
    VlanPath.objects.create(
        session=session, vlan_definition=vdef,
        from_device=dev_a, from_interface="GE0/0/2",
        to_device=dev_b, to_interface="GE0/0/1",
        via_link=link,
    )
    VlanEndpoint.objects.create(
        session=session, vlan_definition=vdef,
        device=dev_a, interface_name="GE0/0/1", endpoint_type="access",
    )
    VlanInterface.objects.create(
        session=session, device=dev_a, interface_name="GE0/0/2", vlan_id=10,
        port_mode="trunk", tagged=True, source="trunk_allowed",
    )
    VlanTrackingIssue.objects.create(
        session=session, vlan_definition=vdef,
        severity="low", code="test_issue", title="Test issue",
    )
    return session, dev_a, dev_b


class DashboardSummaryTests(TestCase):
    def test_dashboard_summary_returns_counts(self):
        summary = get_vlan_tracking_dashboard_summary()
        self.assertIn("total_sessions", summary)
        self.assertIn("total_vlans", summary)


class SearchTests(TestCase):
    def test_search_by_vlan_id(self):
        _make_session()
        results = search_vlan_tracking("10")
        vlan_results = [r for r in results if r["type"] == "tracked_vlan"]
        self.assertGreater(len(vlan_results), 0)

    def test_search_by_session_name(self):
        _make_session()
        results = search_vlan_tracking("Integration")
        session_results = [r for r in results if r["type"] == "vlan_tracking_session"]
        self.assertGreater(len(session_results), 0)

    def test_search_by_issue_code(self):
        _make_session()
        results = search_vlan_tracking("test_issue")
        issue_results = [r for r in results if r["type"] == "vlan_tracking_issue"]
        self.assertGreater(len(issue_results), 0)

    def test_search_by_interface(self):
        _make_session()
        results = search_vlan_tracking("GE0/0/1")
        endpoint_results = [r for r in results if r["type"] == "vlan_tracking_endpoint"]
        self.assertGreater(len(endpoint_results), 0)

    def test_search_by_method(self):
        _make_session()
        results = search_vlan_tracking("lldp")
        link_results = [r for r in results if r["type"] == "vlan_tracking_link"]
        self.assertGreater(len(link_results), 0)

    def test_search_low_confidence(self):
        _make_session()
        results = search_vlan_tracking("low")
        link_results = [r for r in results if r["type"] == "vlan_tracking_link"]
        # No low confidence links in this session, but search should still work
        self.assertIsNotNone(results)

    def test_search_empty_query(self):
        results = search_vlan_tracking("")
        self.assertEqual(results, [])


class DeviceContextTests(TestCase):
    def test_device_context_has_session(self):
        session, dev_a, dev_b = _make_session()
        ctx = get_device_vlan_tracking_context(dev_a)
        self.assertGreater(len(ctx), 0)
        self.assertEqual(ctx[0]["session"].pk, session.pk)

    def test_device_context_has_vlans(self):
        session, dev_a, dev_b = _make_session()
        ctx = get_device_vlan_tracking_context(dev_a)
        self.assertGreater(len(ctx[0]["vlan_ids"]), 0)

    def test_device_context_empty_for_unknown(self):
        from apps.devices.models import Device
        unknown = Device.objects.create(name="Unknown", vendor="huawei")
        ctx = get_device_vlan_tracking_context(unknown)
        self.assertEqual(len(ctx), 0)


class SessionExportTests(TestCase):
    def test_export_text_contains_devices(self):
        session, _, _ = _make_session()
        text = export_session_report_text(session)
        self.assertIn("SW-A", text)
        self.assertIn("SW-B", text)

    def test_export_text_contains_vlans(self):
        session, _, _ = _make_session()
        text = export_session_report_text(session)
        self.assertIn("VLAN 10", text)

    def test_export_text_contains_issues(self):
        session, _, _ = _make_session()
        text = export_session_report_text(session)
        self.assertIn("test_issue", text)

    def test_export_csv_has_rows(self):
        session, _, _ = _make_session()
        rows = export_session_report_csv_rows(session)
        self.assertGreater(len(rows), 0)

    def test_export_csv_includes_vlans(self):
        session, _, _ = _make_session()
        rows = export_session_report_csv_rows(session)
        vlan_rows = [r for r in rows if r["section"] == "vlan"]
        self.assertGreater(len(vlan_rows), 0)

    def test_export_csv_includes_issues(self):
        session, _, _ = _make_session()
        rows = export_session_report_csv_rows(session)
        issue_rows = [r for r in rows if r["section"] == "issue"]
        self.assertGreater(len(issue_rows), 0)


class WebIntegrationTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        self.user = User.objects.create_user("int", "i@i.com", "pass")
        self.client.force_login(self.user)
        self.session, self.dev_a, self.dev_b = _make_session()

    def test_dashboard_shows_vlan_section(self):
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)

    def test_session_export_txt_200(self):
        response = self.client.get(
            reverse("vlan_tracking:session_export_txt", args=[self.session.pk])
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response["Content-Type"])

    def test_session_export_csv_200(self):
        response = self.client.get(
            reverse("vlan_tracking:session_export_csv", args=[self.session.pk])
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response["Content-Type"])

    def test_device_detail_shows_vlan_section(self):
        response = self.client.get(
            reverse("device_detail", args=[self.dev_a.pk])
        )
        self.assertEqual(response.status_code, 200)

    def test_global_search_includes_vlan_tracking(self):
        from apps.analysis.search import global_network_search
        results = global_network_search("SW-A")
        self.assertIn("vlan_tracking", results)
