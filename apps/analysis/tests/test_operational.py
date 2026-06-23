"""Testes do dashboard operacional e páginas de inventário."""

import os

from django.conf import settings
from django.test import TestCase
from django.urls import reverse

from apps.core.tests import *  # noqa: F401, F403 — desabilita auth para testes de view

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
from apps.analysis.services import analyze_config_snapshot
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device

FIXTURES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "tests", "fixtures"
)


def _load_fixture(name: str) -> str:
    path = os.path.join(FIXTURES_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


class OperationalServiceTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        device = Device.objects.create(name="TEST-OP", vendor="huawei")
        snap = ConfigSnapshot.objects.create(
            device=device, raw_config=_load_fixture("circuit_l3.txt"), vendor="huawei"
        )
        analyze_config_snapshot(snap)

    def test_get_operational_summary(self):
        s = get_operational_summary()
        self.assertGreater(s["circuits"], 0)
        self.assertGreater(s["issues"], 0)
        self.assertGreater(s["snapshots"], 0)
        self.assertIn("critical_issues", s)
        self.assertIn("circuit_types", s)

    def test_get_latest_parsed_configs(self):
        result = get_latest_parsed_configs_by_device()
        self.assertGreater(len(result), 0)
        self.assertIsInstance(result[0], ParsedConfig)

    def test_get_recommended_actions(self):
        actions = get_recommended_actions()
        self.assertGreater(len(actions), 0)
        self.assertIn("priority", actions[0])

    def test_filter_circuits_by_type(self):
        result = filter_circuits(circuit_type="l3_transit")
        self.assertGreater(len(result), 0)
        for c in result:
            self.assertEqual(c.circuit_type, "l3_transit")

    def test_filter_circuits_by_interface(self):
        result = filter_circuits(q="Eth-Trunk100")
        self.assertGreater(len(result), 0)

    def test_filter_services_by_type(self):
        result = filter_services(service_type="bng")
        self.assertIsInstance(result, list)

    def test_filter_issues_by_severity(self):
        result = filter_issues(severity="warning")
        for i in result:
            self.assertEqual(i.severity, "warning")

    def test_filter_issues_by_code(self):
        result = filter_issues(code="interface_missing_description")
        for i in result:
            self.assertEqual(i.code, "interface_missing_description")


class InventoryWebTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        snap = ConfigSnapshot.objects.create(
            raw_config=_load_fixture("circuit_l3.txt"), vendor="huawei"
        )
        analyze_config_snapshot(snap)

    def test_circuit_list_200(self):
        r = self.client.get(reverse("circuit_list"))
        self.assertEqual(r.status_code, 200)

    def test_circuit_detail_200(self):
        c = DetectedCircuit.objects.first()
        r = self.client.get(reverse("circuit_detail", kwargs={"pk": c.pk}))
        self.assertEqual(r.status_code, 200)

    def test_circuit_detail_shows_commands(self):
        c = DetectedCircuit.objects.filter(circuit_type="l3_transit").first()
        if c:
            r = self.client.get(reverse("circuit_detail", kwargs={"pk": c.pk}))
            self.assertContains(r, "display ip routing-table")

    def test_circuit_export_csv(self):
        r = self.client.get(reverse("circuit_export"))
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/csv", r["Content-Type"])

    def test_service_list_200(self):
        r = self.client.get(reverse("service_list"))
        self.assertEqual(r.status_code, 200)

    def test_service_detail_200(self):
        s = DetectedService.objects.first()
        if s:
            r = self.client.get(reverse("service_detail", kwargs={"pk": s.pk}))
            self.assertEqual(r.status_code, 200)

    def test_service_export_csv(self):
        r = self.client.get(reverse("service_export"))
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/csv", r["Content-Type"])

    def test_issue_list_200(self):
        r = self.client.get(reverse("issue_list"))
        self.assertEqual(r.status_code, 200)

    def test_issue_detail_200(self):
        i = AnalysisIssue.objects.first()
        r = self.client.get(reverse("issue_detail", kwargs={"pk": i.pk}))
        self.assertEqual(r.status_code, 200)

    def test_issue_detail_shows_suggestion(self):
        i = AnalysisIssue.objects.filter(code="interface_missing_description").first()
        if i:
            r = self.client.get(reverse("issue_detail", kwargs={"pk": i.pk}))
            self.assertContains(r, "description")

    def test_issue_export_csv(self):
        r = self.client.get(reverse("issue_export"))
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/csv", r["Content-Type"])

    def test_filter_circuit_by_type_query(self):
        r = self.client.get("/circuits/?type=l3_transit")
        self.assertEqual(r.status_code, 200)

    def test_filter_issue_by_severity(self):
        r = self.client.get("/issues/?severity=warning")
        self.assertEqual(r.status_code, 200)

    def test_filter_service_by_type(self):
        r = self.client.get("/services/?type=bng")
        self.assertEqual(r.status_code, 200)

    def test_dashboard_200(self):
        r = self.client.get(reverse("dashboard"))
        self.assertEqual(r.status_code, 200)

    def test_dashboard_shows_counts(self):
        r = self.client.get(reverse("dashboard"))
        self.assertContains(r, "Circuitos")
        self.assertContains(r, "Issues")
        self.assertContains(r, "Serviços")
