"""Testes de páginas e serviços de dispositivo."""

import os

from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from apps.analysis.models import (
    AnalysisIssue,
    DetectedCircuit,
    DetectedService,
    ParsedConfig,
)
from apps.analysis.services import analyze_config_snapshot
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device
from apps.devices.operational import (
    filter_devices,
    get_device_recommended_actions,
    get_device_status,
    get_device_summary,
    get_device_timeline,
)

FIXTURES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "tests", "fixtures"
)


def _load_fixture(name: str) -> str:
    path = os.path.join(FIXTURES_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


class DeviceOperationalServiceTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.device = Device.objects.create(
            name="TESTE-STATUS", vendor="huawei", hostname="TESTE-STATUS"
        )
        snap = ConfigSnapshot.objects.create(
            device=cls.device, raw_config=_load_fixture("circuit_l3.txt"), vendor="huawei"
        )
        cls.parsed = analyze_config_snapshot(snap)

    def test_status_no_data_no_snapshot(self):
        d2 = Device.objects.create(name="NO-SNAP", vendor="huawei")
        self.assertEqual(get_device_status(d2), "no_data")

    def test_status_ok_no_issues(self):
        # Clear all issues for this device
        last_snap = ConfigSnapshot.objects.filter(device=self.device).first()
        AnalysisIssue.objects.filter(snapshot=last_snap).delete()
        self.assertEqual(get_device_status(self.device), "ok")

    def test_status_critical(self):
        last_snap = ConfigSnapshot.objects.filter(device=self.device).first()
        AnalysisIssue.objects.create(
            snapshot=last_snap, severity="critical",
            code="test", title="Test critical"
        )
        self.assertEqual(get_device_status(self.device), "critical")

    def test_get_device_summary(self):
        s = get_device_summary(self.device)
        self.assertEqual(s["device"], self.device)
        self.assertGreater(s["total_snapshots"], 0)
        self.assertIsNotNone(s["last_snapshot"])

    def test_get_device_timeline(self):
        tl = get_device_timeline(self.device)
        self.assertGreater(len(tl), 0)

    def test_get_device_recommended_actions(self):
        actions = get_device_recommended_actions(self.device)
        self.assertGreater(len(actions), 0)

    def test_filter_devices(self):
        result = filter_devices()
        names = [d["device"].name for d in result]
        self.assertIn("TESTE-STATUS", names)

    def test_filter_devices_by_vendor(self):
        result = filter_devices(vendor="huawei")
        self.assertGreater(len(result), 0)

    def test_filter_devices_by_q(self):
        result = filter_devices(q="TESTE-STATUS")
        self.assertEqual(len(result), 1)

    def test_last_snapshot_by_date(self):
        """Verifica que o último snapshot é escolhido por data (pk maior = mais recente)."""
        d2 = Device.objects.create(name="DATE-TEST", vendor="huawei")
        snap1 = ConfigSnapshot.objects.create(
            device=d2, raw_config="#\nsysname TEST\n#\n", vendor="huawei",
        )
        snap2 = ConfigSnapshot.objects.create(
            device=d2, raw_config="#\nsysname TEST2\n#\n", vendor="huawei",
        )
        # snap2 is newer (auto_now_add, higher pk)
        s = get_device_summary(d2)
        self.assertEqual(s["last_snapshot"].pk, max(snap1.pk, snap2.pk))


class DeviceWebTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.device = Device.objects.create(name="WEB-DEVICE", vendor="huawei")
        snap = ConfigSnapshot.objects.create(
            device=cls.device, raw_config=_load_fixture("circuit_l3.txt"), vendor="huawei"
        )
        analyze_config_snapshot(snap)
        cls.test_user = User.objects.create_user(username="devweb", password="pass123")

    def setUp(self):
        super().setUp()
        self.client.force_login(self.test_user)

    def test_device_list_200(self):
        r = self.client.get(reverse("device_list"))
        self.assertEqual(r.status_code, 200)

    def test_device_list_shows_device(self):
        r = self.client.get(reverse("device_list"))
        self.assertContains(r, "WEB-DEVICE")

    def test_device_detail_200(self):
        r = self.client.get(reverse("device_detail", kwargs={"pk": self.device.pk}))
        self.assertEqual(r.status_code, 200)

    def test_device_detail_shows_snapshots(self):
        r = self.client.get(reverse("device_detail", kwargs={"pk": self.device.pk}))
        self.assertContains(r, "Snapshot")

    def test_device_detail_shows_circuits(self):
        r = self.client.get(reverse("device_detail", kwargs={"pk": self.device.pk}))
        self.assertContains(r, "Circuitos")

    def test_device_detail_shows_services(self):
        r = self.client.get(reverse("device_detail", kwargs={"pk": self.device.pk}))
        self.assertContains(r, "Serviços")

    def test_device_detail_shows_issues(self):
        r = self.client.get(reverse("device_detail", kwargs={"pk": self.device.pk}))
        self.assertContains(r, "Issues")

    def test_device_detail_shows_timeline(self):
        r = self.client.get(reverse("device_detail", kwargs={"pk": self.device.pk}))
        self.assertContains(r, "Timeline")

    def test_device_detail_shows_actions(self):
        r = self.client.get(reverse("device_detail", kwargs={"pk": self.device.pk}))
        self.assertContains(r, "Ações Recomendadas")

    def test_device_export_csv(self):
        r = self.client.get(reverse("device_export"))
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/csv", r["Content-Type"])

    def test_filter_device_by_vendor(self):
        r = self.client.get("/devices/?vendor=huawei")
        self.assertEqual(r.status_code, 200)

    def test_filter_device_by_q(self):
        r = self.client.get("/devices/?q=WEB")
        self.assertEqual(r.status_code, 200)

    def test_inventory_filters_device(self):
        """Filtro por device em /circuits/ deve funcionar."""
        r = self.client.get(f"/circuits/?device=WEB-DEVICE")
        self.assertEqual(r.status_code, 200)

    def test_inventory_filters_vendor(self):
        r = self.client.get("/circuits/?vendor=huawei")
        self.assertEqual(r.status_code, 200)

    def test_inventory_filters_min_confidence(self):
        r = self.client.get("/circuits/?min_confidence=0.5")
        self.assertEqual(r.status_code, 200)

    def test_issues_filters_device(self):
        r = self.client.get(f"/issues/?device=WEB-DEVICE")
        self.assertEqual(r.status_code, 200)

    def test_services_filters_device(self):
        r = self.client.get(f"/services/?device=WEB-DEVICE")
        self.assertEqual(r.status_code, 200)
