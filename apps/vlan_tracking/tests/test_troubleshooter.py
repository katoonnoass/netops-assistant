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
    VlanTrackingIssue,
)
from ..services import create_session_from_devices
from ..tests.test_vlan_tracking import SIMPLE_L2_CONFIG, SIMPLE_L2_CONFIG_2, _create_device_and_snapshot
from ..troubleshooter import (
    build_vlan_troubleshooting_report,
    build_vlan_endpoint_summary,
    build_vlan_issue_recommendations,
    build_vlan_path_risk_summary,
    build_vlan_validation_commands,
    classify_vlan_health,
    export_vlan_report_csv_rows,
    export_vlan_report_text,
)


def _make_basic_session():
    dev_a, snap_a = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG)
    dev_b, snap_b = _create_device_and_snapshot("SW-B", SIMPLE_L2_CONFIG_2)
    session = create_session_from_devices(
        "Troubleshoot Test", [(dev_a, snap_a), (dev_b, snap_b)]
    )
    link = DeviceLink.objects.create(
        session=session, device_a=dev_a, interface_a="GigabitEthernet0/0/2",
        device_b=dev_b, interface_b="GigabitEthernet0/0/1",
        discovery_method="lldp", confidence="high",
    )
    vdef = VlanDefinition.objects.create(session=session, vlan_id=10, name="Clientes")
    VlanPath.objects.create(
        session=session, vlan_definition=vdef,
        from_device=dev_a, from_interface="GigabitEthernet0/0/2",
        to_device=dev_b, to_interface="GigabitEthernet0/0/1",
        via_link=link,
    )
    VlanEndpoint.objects.create(
        session=session, vlan_definition=vdef,
        device=dev_a, interface_name="GE0/0/1",
        endpoint_type="access",
    )
    VlanEndpoint.objects.create(
        session=session, vlan_definition=vdef,
        device=dev_b, interface_name="GE0/0/2",
        endpoint_type="subinterface_l3",
    )
    VlanInterface.objects.create(
        session=session, device=dev_a, interface_name="GE0/0/2", vlan_id=10,
        port_mode="trunk", tagged=True, source="trunk_allowed",
    )
    VlanInterface.objects.create(
        session=session, device=dev_b, interface_name="GE0/0/1", vlan_id=10,
        port_mode="trunk", tagged=True, source="trunk_allowed",
    )
    return session


class HealthClassificationTests(TestCase):
    def test_health_ok(self):
        session = _make_basic_session()
        health = classify_vlan_health(session, 10)
        self.assertEqual(health["status"], "ok")

    def test_health_no_data(self):
        session = _make_basic_session()
        health = classify_vlan_health(session, 999)
        self.assertEqual(health["status"], "no_data")

    def test_health_critical_endpoint_without_path(self):
        dev, snap = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG)
        session = create_session_from_devices("Critical Test", [(dev, snap)])
        vdef = VlanDefinition.objects.create(session=session, vlan_id=10)
        VlanEndpoint.objects.create(
            session=session, vlan_definition=vdef,
            device=dev, interface_name="GE0/0/1", endpoint_type="access",
        )
        health = classify_vlan_health(session, 10)
        self.assertEqual(health["status"], "critical")

    def test_health_attention_low_confidence(self):
        dev_a, snap_a = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG)
        dev_b, snap_b = _create_device_and_snapshot("SW-B", SIMPLE_L2_CONFIG_2)
        session = create_session_from_devices("Low Conf", [(dev_a, snap_a), (dev_b, snap_b)])
        link = DeviceLink.objects.create(
            session=session, device_a=dev_a, interface_a="GE0/0/2",
            device_b=dev_b, interface_b="GE0/0/1",
            confidence="low", discovery_method="subnet",
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
            device=dev_a, interface_name="GE0/0/1", endpoint_type="access",
        )
        VlanTrackingIssue.objects.create(
            session=session, vlan_definition=vdef,
            severity="low", code="vlan_path_uses_low_confidence_link",
            title="Low confidence path",
        )
        health = classify_vlan_health(session, 10)
        self.assertEqual(health["status"], "attention")

    def test_health_incomplete_single_device(self):
        dev, snap = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG)
        session = create_session_from_devices("Incomplete", [(dev, snap)])
        VlanDefinition.objects.create(session=session, vlan_id=10)
        health = classify_vlan_health(session, 10)
        self.assertEqual(health["status"], "incomplete")


class ReportTests(TestCase):
    def test_build_report_exists(self):
        session = _make_basic_session()
        report = build_vlan_troubleshooting_report(session, 10)
        self.assertNotIn("error", report)
        self.assertEqual(report["vlan"]["id"], 10)
        self.assertEqual(report["vlan"]["name"], "Clientes")

    def test_build_report_nonexistent(self):
        session = _make_basic_session()
        report = build_vlan_troubleshooting_report(session, 999)
        self.assertIn("error", report)

    def test_report_has_devices(self):
        session = _make_basic_session()
        report = build_vlan_troubleshooting_report(session, 10)
        self.assertIn("SW-A", report["devices"])
        self.assertIn("SW-B", report["devices"])

    def test_report_has_endpoints(self):
        session = _make_basic_session()
        report = build_vlan_troubleshooting_report(session, 10)
        self.assertGreater(len(report["endpoints"]["access"]), 0)
        self.assertGreater(len(report["endpoints"]["subinterface_l3"]), 0)

    def test_report_has_paths(self):
        session = _make_basic_session()
        report = build_vlan_troubleshooting_report(session, 10)
        self.assertGreater(len(report["paths"]), 0)

    def test_report_has_health(self):
        session = _make_basic_session()
        report = build_vlan_troubleshooting_report(session, 10)
        self.assertEqual(report["health"]["label"], "OK")

    def test_report_has_risk_summary(self):
        session = _make_basic_session()
        report = build_vlan_troubleshooting_report(session, 10)
        self.assertIn("total", report["risk"])

    def test_endpoint_summary_separates_types(self):
        session = _make_basic_session()
        summary = build_vlan_endpoint_summary(session, 10)
        self.assertIn("access", summary)
        self.assertIn("subinterface_l3", summary)

    def test_recommendations(self):
        session = _make_basic_session()
        VlanTrackingIssue.objects.create(
            session=session,
            vlan_definition=VlanDefinition.objects.get(session=session, vlan_id=10),
            severity="low", code="vlan_path_uses_low_confidence_link",
            title="Low confidence",
        )
        recs = build_vlan_issue_recommendations(session, 10)
        self.assertGreater(len(recs), 0)

    def test_risk_summary_counts(self):
        session = _make_basic_session()
        risk = build_vlan_path_risk_summary(session, 10)
        self.assertGreater(risk["total"], 0)


class CommandTests(TestCase):
    def test_huawei_commands(self):
        dev, snap = _create_device_and_snapshot("SW-A", SIMPLE_L2_CONFIG, vendor="huawei")
        session = create_session_from_devices("Huawei Cmds", [(dev, snap)])
        VlanDefinition.objects.create(session=session, vlan_id=10)
        VlanInterface.objects.create(
            session=session, device=dev, interface_name="GE0/0/1",
            vlan_id=10, port_mode="access", source="access_vlan",
        )
        commands = build_vlan_validation_commands(session, 10)
        self.assertGreater(len(commands), 0)
        self.assertIn("display vlan 10", commands[0]["commands"])

    def test_cisco_commands(self):
        dev = Device.objects.create(name="Cisco-SW", vendor="cisco")
        from apps.config_archive.models import ConfigSnapshot
        snap = ConfigSnapshot.objects.create(device=dev, raw_config="", vendor="cisco", source="paste")
        session = create_session_from_devices("Cisco Cmds", [(dev, snap)])
        VlanDefinition.objects.create(session=session, vlan_id=20)
        VlanInterface.objects.create(
            session=session, device=dev, interface_name="Gi0/1",
            vlan_id=20, port_mode="trunk", tagged=True, source="trunk_allowed",
        )
        commands = build_vlan_validation_commands(session, 20)
        self.assertGreater(len(commands), 0)
        all_cmds = [cmd for c in commands for cmd in c["commands"]]
        self.assertTrue(any("show vlan id 20" in cmd for cmd in all_cmds))

    def test_subinterface_commands(self):
        dev, snap = _create_device_and_snapshot("RTR-A", SIMPLE_L2_CONFIG, vendor="huawei")
        session = create_session_from_devices("Subif Cmds", [(dev, snap)])
        VlanDefinition.objects.create(session=session, vlan_id=100)
        VlanInterface.objects.create(
            session=session, device=dev, interface_name="GE0/0/2.100",
            vlan_id=100, port_mode="subinterface", source="dot1q",
        )
        commands = build_vlan_validation_commands(session, 100)
        all_cmds = [cmd for c in commands for cmd in c["commands"]]
        has_subif = any("display ip interface brief" in cmd for cmd in all_cmds)
        self.assertTrue(has_subif)

    def test_unknown_vendor_uses_huawei_default(self):
        dev = Device.objects.create(name="SW-X", vendor="unknown")
        from apps.config_archive.models import ConfigSnapshot
        snap = ConfigSnapshot.objects.create(device=dev, raw_config="", vendor="unknown", source="paste")
        session = create_session_from_devices("Unknown", [(dev, snap)])
        VlanDefinition.objects.create(session=session, vlan_id=10)
        VlanInterface.objects.create(
            session=session, device=dev, interface_name="GE0/0/1",
            vlan_id=10, port_mode="access", source="access_vlan",
        )
        commands = build_vlan_validation_commands(session, 10)
        self.assertGreater(len(commands), 0)


class ExportTests(TestCase):
    def test_export_text_contains_status(self):
        session = _make_basic_session()
        text = export_vlan_report_text(session, 10)
        self.assertIn("OK", text)
        self.assertIn("Caminho", text)
        self.assertIn("SW-A", text)

    def test_export_text_contains_commands(self):
        session = _make_basic_session()
        text = export_vlan_report_text(session, 10)
        self.assertIn("display vlan 10", text)

    def test_export_csv_has_rows(self):
        session = _make_basic_session()
        rows = export_vlan_report_csv_rows(session, 10)
        self.assertGreater(len(rows), 0)
        sections = set(r["section"] for r in rows)
        self.assertIn("device", sections)
        self.assertIn("endpoint", sections)
        self.assertIn("path", sections)

    def test_export_csv_nonexistent(self):
        session = _make_basic_session()
        rows = export_vlan_report_csv_rows(session, 999)
        self.assertGreater(len(rows), 0)
        self.assertIn("error", rows[0]["section"])


class WebViewsTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        self.user = User.objects.create_user("trouble", "t@t.com", "pass")
        self.client.force_login(self.user)
        self.session = _make_basic_session()

    def test_search_page_200(self):
        response = self.client.get(
            reverse("vlan_tracking:troubleshoot_search", args=[self.session.pk])
        )
        self.assertEqual(response.status_code, 200)

    def test_detail_page_200(self):
        response = self.client.get(
            reverse("vlan_tracking:troubleshoot_detail", args=[self.session.pk, 10])
        )
        self.assertEqual(response.status_code, 200)

    def test_detail_shows_health(self):
        response = self.client.get(
            reverse("vlan_tracking:troubleshoot_detail", args=[self.session.pk, 10])
        )
        self.assertContains(response, "OK")

    def test_detail_shows_commands(self):
        response = self.client.get(
            reverse("vlan_tracking:troubleshoot_detail", args=[self.session.pk, 10])
        )
        self.assertContains(response, "display vlan")

    def test_export_txt_returns_text(self):
        response = self.client.get(
            reverse("vlan_tracking:troubleshoot_export_txt", args=[self.session.pk, 10])
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response["Content-Type"])

    def test_export_csv_returns_csv(self):
        response = self.client.get(
            reverse("vlan_tracking:troubleshoot_export_csv", args=[self.session.pk, 10])
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response["Content-Type"])

    def test_session_detail_has_troubleshoot_link(self):
        response = self.client.get(
            reverse("vlan_tracking:session_detail", args=[self.session.pk])
        )
        self.assertContains(response, "Troubleshoot VLAN")

    def test_vlan_detail_has_troubleshoot_link(self):
        response = self.client.get(
            reverse("vlan_tracking:vlan_detail", args=[self.session.pk, 10])
        )
        self.assertContains(response, "Relatório Operacional")
