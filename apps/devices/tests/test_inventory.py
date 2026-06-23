"""Testes do módulo de Inventário e Snapshots.

Cobre:
- Device model novos campos
- ConfigSnapshot novos campos e hash dedup
- Helper services (operational.py)
- Views (device_list, device_detail, snapshot_list, snapshot_upload, device_compare)
- Dashboard novos cards
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.analysis.models import AnalysisIssue, ConfigComparison, DetectedCircuit, DetectedService, ParsedConfig
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device
from apps.devices.operational import (
    filter_devices,
    get_device_status,
    get_devices_without_snapshot_count,
    get_latest_issue_summary,
    get_latest_parsed_config,
    get_latest_snapshot,
    get_snapshots_for_device,
    get_snapshots_last_7_days,
    get_top_issues_devices,
    get_vendor_summary,
)


# ── Device Model Tests ────────────────────────────────────────────────


class DeviceModelTests(TestCase):
    def test_create_device_minimal(self):
        d = Device.objects.create(name="test-device")
        self.assertEqual(d.name, "test-device")
        self.assertEqual(d.vendor, "huawei")
        self.assertEqual(d.platform, "")
        self.assertEqual(d.role, "")
        self.assertEqual(d.site, "")
        self.assertIsNone(d.ip_address)
        self.assertEqual(d.hostname, "")

    def test_create_device_full(self):
        d = Device.objects.create(
            name="core-router",
            vendor="cisco",
            platform="ASR9000",
            role="core",
            site="DC-SP",
            ip_address="10.0.0.1",
            hostname="core-router.example.com",
            description="Core router SP",
        )
        self.assertEqual(d.name, "core-router")
        self.assertEqual(d.vendor, "cisco")
        self.assertEqual(d.platform, "ASR9000")
        self.assertEqual(d.role, "core")
        self.assertEqual(d.site, "DC-SP")
        self.assertEqual(d.ip_address, "10.0.0.1")
        self.assertEqual(d.hostname, "core-router.example.com")

    def test_device_str(self):
        d = Device.objects.create(name="MEU-ROUTER")
        self.assertEqual(str(d), "MEU-ROUTER")

    def test_device_role_choices(self):
        d = Device.objects.create(name="bng-device", role="bng")
        self.assertEqual(d.get_role_display(), "BNG")

    def test_device_ordering(self):
        Device.objects.create(name="z-device")
        Device.objects.create(name="a-device")
        names = list(Device.objects.values_list("name", flat=True))
        self.assertEqual(names, ["a-device", "z-device"])

    def test_device_unique_name(self):
        Device.objects.create(name="unique")
        with self.assertRaises(Exception):
            Device.objects.create(name="unique")


# ── ConfigSnapshot Model Tests ────────────────────────────────────────


class ConfigSnapshotModelTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="snap-test-device")

    def test_create_snapshot_minimal(self):
        snap = ConfigSnapshot.objects.create(
            device=self.device,
            raw_config="hostname TEST\n",
        )
        self.assertEqual(snap.device, self.device)
        self.assertEqual(snap.raw_config, "hostname TEST\n")
        self.assertEqual(snap.vendor, "")
        self.assertEqual(snap.source, "paste")
        self.assertFalse(snap.is_baseline)
        self.assertEqual(snap.name, "")
        self.assertEqual(snap.description, "")

    def test_config_hash_generated_on_save(self):
        raw = "hostname TEST\ninterface G0/0/0\n ip address 10.0.0.1 255.255.255.252\n#\n"
        expected_hash = hashlib.sha256(raw.strip().replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")).hexdigest()
        snap = ConfigSnapshot.objects.create(device=self.device, raw_config=raw)
        self.assertEqual(snap.config_hash, expected_hash)

    def test_config_hash_normalization(self):
        """CRLF e trailing whitespace são normalizados antes do hash."""
        raw_crlf = "hostname TEST\r\ninterface G0/0/0\r\n#\r\n"
        raw_lf = "hostname TEST\ninterface G0/0/0\n#\n"
        snap1 = ConfigSnapshot.objects.create(device=self.device, raw_config=raw_crlf)
        snap2 = ConfigSnapshot.objects.create(device=self.device, raw_config=raw_lf)
        self.assertEqual(snap1.config_hash, snap2.config_hash)

    def test_hash_short_property(self):
        raw = "hostname TEST\n"
        snap = ConfigSnapshot.objects.create(device=self.device, raw_config=raw)
        self.assertEqual(len(snap.hash_short), 12)
        self.assertEqual(snap.hash_short, snap.config_hash[:12])

    def test_reject_duplicate_hash_same_device(self):
        raw = "hostname DUPLICATE\n"
        snap1 = ConfigSnapshot.objects.create(device=self.device, raw_config=raw)
        snap2 = ConfigSnapshot(device=self.device, raw_config=raw)
        dup = snap2.is_duplicate_of()
        self.assertIsNotNone(dup)
        self.assertEqual(dup.pk, snap1.pk)

    def test_allow_same_hash_different_device(self):
        raw = "hostname SAME\n"
        other_device = Device.objects.create(name="other-device")
        snap1 = ConfigSnapshot.objects.create(device=self.device, raw_config=raw)
        snap2 = ConfigSnapshot.objects.create(device=other_device, raw_config=raw)
        self.assertEqual(snap1.config_hash, snap2.config_hash)
        # is_duplicate_of should return None for different devices
        self.assertIsNone(snap2.is_duplicate_of())

    def test_captured_at_field(self):
        dt = timezone.make_aware(datetime(2025, 6, 15, 10, 30))
        snap = ConfigSnapshot.objects.create(
            device=self.device, raw_config="hostname T\n", captured_at=dt
        )
        self.assertEqual(snap.captured_at, dt)

    def test_baseline_flag(self):
        snap = ConfigSnapshot.objects.create(
            device=self.device, raw_config="hostname BL\n", is_baseline=True
        )
        self.assertTrue(snap.is_baseline)

    def test_name_and_description(self):
        snap = ConfigSnapshot.objects.create(
            device=self.device,
            raw_config="hostname ND\n",
            name="Antes da mudança",
            description="Snapshot antes da migração BGP",
        )
        self.assertEqual(snap.name, "Antes da mudança")
        self.assertEqual(snap.description, "Snapshot antes da migração BGP")

    def test_str_with_name(self):
        snap = ConfigSnapshot.objects.create(
            device=self.device,
            raw_config="hostname STR\n",
            name="Meu Snapshot",
        )
        self.assertIn("Meu Snapshot", str(snap))
        self.assertIn("snap-test-device", str(snap))


# ── Helper Service Tests ──────────────────────────────────────────────


class HelperServiceTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="helper-test")
        self.other_device = Device.objects.create(name="other-helper")

    def _create_snap(self, device, raw="hostname T\n", **kwargs):
        return ConfigSnapshot.objects.create(device=device, raw_config=raw, **kwargs)

    def test_get_latest_snapshot(self):
        s1 = self._create_snap(self.device)
        s2 = self._create_snap(self.device)
        self.assertEqual(get_latest_snapshot(self.device).pk, s2.pk)

    def test_get_latest_snapshot_no_snap(self):
        new_dev = Device.objects.create(name="empty")
        self.assertIsNone(get_latest_snapshot(new_dev))

    def test_get_latest_parsed_config(self):
        snap = self._create_snap(self.device)
        parsed = ParsedConfig.objects.create(
            snapshot=snap, parsed_data={"test": True}
        )
        result = get_latest_parsed_config(self.device)
        self.assertEqual(result.pk, parsed.pk)

    def test_get_latest_parsed_config_no_snap(self):
        new_dev = Device.objects.create(name="no-snap")
        self.assertIsNone(get_latest_parsed_config(new_dev))

    def test_get_latest_parsed_config_no_parsed(self):
        self._create_snap(self.device)
        self.assertIsNone(get_latest_parsed_config(self.device))

    def test_get_latest_issue_summary_no_snap(self):
        new_dev = Device.objects.create(name="empty-issues")
        summary = get_latest_issue_summary(new_dev)
        self.assertEqual(summary["total"], 0)

    def test_get_latest_issue_summary_with_issues(self):
        snap = self._create_snap(self.device)
        AnalysisIssue.objects.create(
            snapshot=snap, severity="critical", title="C1", code="c1"
        )
        AnalysisIssue.objects.create(
            snapshot=snap, severity="warning", title="W1", code="w1"
        )
        AnalysisIssue.objects.create(
            snapshot=snap, severity="info", title="I1", code="i1"
        )
        summary = get_latest_issue_summary(self.device)
        self.assertEqual(summary["critical"], 1)
        self.assertEqual(summary["warning"], 1)
        self.assertEqual(summary["info"], 1)
        self.assertEqual(summary["total"], 3)

    def test_get_snapshots_for_device(self):
        s1 = self._create_snap(self.device)
        s2 = self._create_snap(self.device)
        snaps = get_snapshots_for_device(self.device)
        self.assertEqual(len(snaps), 2)
        # Ordered by most recent first
        self.assertEqual(snaps[0].pk, s2.pk)

    def test_get_snapshots_for_device_other_device(self):
        self._create_snap(self.device)
        snaps = get_snapshots_for_device(self.other_device)
        self.assertEqual(len(snaps), 0)

    def test_get_vendor_summary(self):
        Device.objects.all().delete()
        Device.objects.create(name="v1", vendor="huawei")
        Device.objects.create(name="v2", vendor="huawei")
        Device.objects.create(name="v3", vendor="cisco")
        summary = get_vendor_summary()
        huawei = next(s for s in summary if s["vendor"] == "huawei")
        cisco = next(s for s in summary if s["vendor"] == "cisco")
        self.assertEqual(huawei["total"], 2)
        self.assertEqual(cisco["total"], 1)

    def test_get_top_issues_devices(self):
        snap = self._create_snap(self.device)
        AnalysisIssue.objects.create(
            snapshot=snap, severity="critical", title="C1", code="c1"
        )
        top = get_top_issues_devices(5)
        self.assertEqual(len(top), 1)
        self.assertEqual(top[0]["device"].pk, self.device.pk)
        self.assertEqual(top[0]["critical"], 1)

    def test_get_top_issues_devices_limit(self):
        d2 = Device.objects.create(name="d2")
        s1 = self._create_snap(self.device, raw="hostname S1\n")
        s2 = self._create_snap(d2, raw="hostname S2\n")
        AnalysisIssue.objects.create(
            snapshot=s1, severity="critical", title="C", code="c"
        )
        AnalysisIssue.objects.create(
            snapshot=s2, severity="warning", title="W", code="w"
        )
        top = get_top_issues_devices(1)
        self.assertEqual(len(top), 1)

    def test_get_devices_without_snapshot_count(self):
        Device.objects.all().delete()
        d1 = Device.objects.create(name="no-snap-1")
        d2 = Device.objects.create(name="no-snap-2")
        d3 = Device.objects.create(name="with-snap")
        ConfigSnapshot.objects.create(device=d3, raw_config="hostname T\n")
        self.assertEqual(get_devices_without_snapshot_count(), 2)

    def test_get_snapshots_last_7_days(self):
        self._create_snap(self.device)
        count = get_snapshots_last_7_days()
        self.assertEqual(count, 1)

    def test_get_device_status_no_data(self):
        new_dev = Device.objects.create(name="no-data")
        self.assertEqual(get_device_status(new_dev), "no_data")

    def test_get_device_status_no_parsed(self):
        self._create_snap(self.device)
        self.assertEqual(get_device_status(self.device), "no_data")

    def test_get_device_status_ok(self):
        snap = self._create_snap(self.device)
        ParsedConfig.objects.create(snapshot=snap, parsed_data={})
        self.assertEqual(get_device_status(self.device), "ok")

    def test_get_device_status_critical(self):
        snap = self._create_snap(self.device)
        ParsedConfig.objects.create(snapshot=snap, parsed_data={})
        AnalysisIssue.objects.create(
            snapshot=snap, severity="critical", title="C", code="c"
        )
        self.assertEqual(get_device_status(self.device), "critical")

    def test_get_device_status_warning(self):
        snap = self._create_snap(self.device)
        ParsedConfig.objects.create(snapshot=snap, parsed_data={})
        AnalysisIssue.objects.create(
            snapshot=snap, severity="warning", title="W", code="w"
        )
        self.assertEqual(get_device_status(self.device), "warning")

    def test_filter_devices_by_role(self):
        Device.objects.create(name="core-rtr", role="core")
        Device.objects.create(name="access-sw", role="access")
        results = filter_devices(role="core")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["device"].name, "core-rtr")

    def test_filter_devices_by_site(self):
        Device.objects.create(name="sp1", site="DC-SP")
        Device.objects.create(name="rj1", site="DC-RJ")
        results = filter_devices(site="sp")
        self.assertEqual(len(results), 1)

    def test_filter_devices_by_platform(self):
        Device.objects.create(name="rtr", platform="NE40E")
        Device.objects.create(name="sw", platform="CE6800")
        results = filter_devices(platform="NE40")
        self.assertEqual(len(results), 1)


# ── View Tests ────────────────────────────────────────────────────────


class DeviceListViewTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="view-test-device")
        self.user = User.objects.create_user(username="viewer", password="viewer123")
        self.client.login(username="viewer", password="viewer123")

    def test_device_list_anonymous_redirect(self):
        """Anonymous user sees device list (test middleware auto-auth)."""
        self.client.logout()
        response = self.client.get(reverse("device_list"))
        self.assertEqual(response.status_code, 200)

    def test_device_list_status(self):
        response = self.client.get(reverse("device_list"))
        self.assertEqual(response.status_code, 200)

    def test_device_list_contains_device(self):
        response = self.client.get(reverse("device_list"))
        self.assertContains(response, "view-test-device")

    def test_device_list_empty(self):
        Device.objects.all().delete()
        response = self.client.get(reverse("device_list"))
        self.assertContains(response, "Nenhum dispositivo")

    def test_device_list_filter_vendor(self):
        response = self.client.get(reverse("device_list"), {"vendor": "huawei"})
        self.assertEqual(response.status_code, 200)

    def test_device_list_filter_status(self):
        response = self.client.get(reverse("device_list"), {"status": "no_data"})
        self.assertEqual(response.status_code, 200)

    def test_device_list_search(self):
        response = self.client.get(reverse("device_list"), {"q": "view-test"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "view-test-device")

    def test_device_list_role_filter(self):
        d = Device.objects.create(name="core-test", role="core")
        response = self.client.get(reverse("device_list"), {"role": "core"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "core-test")


class DeviceDetailViewTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="detail-test")
        self.user = User.objects.create_user(username="viewer2", password="viewer123")
        self.client.login(username="viewer2", password="viewer123")

    def test_device_detail_status(self):
        response = self.client.get(reverse("device_detail", args=[self.device.pk]))
        self.assertEqual(response.status_code, 200)

    def test_device_detail_contains_name(self):
        response = self.client.get(reverse("device_detail", args=[self.device.pk]))
        self.assertContains(response, "detail-test")

    def test_device_detail_404(self):
        response = self.client.get(reverse("device_detail", args=[9999]))
        self.assertEqual(response.status_code, 404)

    def test_device_detail_shows_snapshot_link(self):
        snap = ConfigSnapshot.objects.create(
            device=self.device, raw_config="hostname T\n"
        )
        parsed = ParsedConfig.objects.create(snapshot=snap, parsed_data={})
        response = self.client.get(reverse("device_detail", args=[self.device.pk]))
        self.assertContains(response, "Novo Snapshot")
        self.assertContains(response, "Snapshots")


class SnapshotListViewTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="snap-list-test")
        self.user = User.objects.create_user(username="viewer3", password="viewer123")
        self.client.login(username="viewer3", password="viewer123")

    def test_snapshot_list_status(self):
        ConfigSnapshot.objects.create(
            device=self.device, raw_config="hostname T\n"
        )
        response = self.client.get(
            reverse("device_snapshot_list", args=[self.device.pk])
        )
        self.assertEqual(response.status_code, 200)

    def test_snapshot_list_empty(self):
        response = self.client.get(
            reverse("device_snapshot_list", args=[self.device.pk])
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Nenhum snapshot")

    def test_snapshot_list_contains_snapshot(self):
        snap = ConfigSnapshot.objects.create(
            device=self.device, raw_config="hostname SHOW\n", name="TestSnap"
        )
        response = self.client.get(
            reverse("device_snapshot_list", args=[self.device.pk])
        )
        self.assertContains(response, "TestSnap")
        self.assertContains(response, snap.hash_short)

    def test_snapshot_list_404(self):
        response = self.client.get(
            reverse("device_snapshot_list", args=[9999])
        )
        self.assertEqual(response.status_code, 404)


class SnapshotUploadViewTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="upload-test")
        self.url = reverse("device_snapshot_upload", args=[self.device.pk])
        self.user = User.objects.create_superuser(username="operator1", password="op123", email="")
        self.client.login(username="operator1", password="op123")

    def test_upload_get_status(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_upload_post_creates_snapshot(self):
        response = self.client.post(self.url, {
            "raw_config": "hostname UPLOAD\n",
        })
        self.assertEqual(ConfigSnapshot.objects.filter(device=self.device).count(), 1)
        # Should redirect to analysis detail
        self.assertEqual(response.status_code, 302)

    def test_upload_post_empty_config(self):
        response = self.client.post(self.url, {"raw_config": ""})
        self.assertEqual(ConfigSnapshot.objects.count(), 0)
        self.assertContains(response, "não pode estar vazia")

    def test_upload_post_duplicate_blocked(self):
        self.client.post(self.url, {"raw_config": "hostname DUP\n"})
        response = self.client.post(self.url, {"raw_config": "hostname DUP\n"})
        self.assertEqual(ConfigSnapshot.objects.filter(device=self.device).count(), 1)
        # Should redirect to snapshot list with warning
        self.assertRedirects(response, reverse("device_snapshot_list", args=[self.device.pk]))

    def test_upload_with_name_and_baseline(self):
        response = self.client.post(self.url, {
            "raw_config": "hostname BL\n",
            "name": "Config Baseline",
            "is_baseline": "on",
        })
        self.assertEqual(response.status_code, 302)
        snap = ConfigSnapshot.objects.filter(device=self.device).first()
        self.assertIsNotNone(snap)
        self.assertEqual(snap.name, "Config Baseline")
        self.assertTrue(snap.is_baseline)

    def test_upload_captured_at_is_timezone_aware(self):
        response = self.client.post(self.url, {
            "raw_config": "hostname TZ-AWARE\n",
            "captured_at": "2026-06-21T03:30",
        })

        self.assertEqual(response.status_code, 302)
        snapshot = ConfigSnapshot.objects.get(device=self.device)
        self.assertTrue(timezone.is_aware(snapshot.captured_at))

    def test_upload_404(self):
        response = self.client.get(
            reverse("device_snapshot_upload", args=[9999])
        )
        self.assertEqual(response.status_code, 404)


class DeviceCompareViewTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="compare-test")
        self.url = reverse("device_compare", args=[self.device.pk])
        self.snap1 = ConfigSnapshot.objects.create(
            device=self.device, raw_config="hostname A\n"
        )
        self.snap2 = ConfigSnapshot.objects.create(
            device=self.device, raw_config="hostname B\n"
        )
        self.user = User.objects.create_superuser(username="operator2", password="op123")
        self.client.login(username="operator2", password="op123")

    def test_compare_get_status(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_compare_post_creates_comparison(self):
        response = self.client.post(self.url, {
            "base_snapshot": self.snap1.pk,
            "target_snapshot": self.snap2.pk,
        })
        self.assertEqual(ConfigComparison.objects.count(), 1)
        self.assertEqual(response.status_code, 302)

    def test_compare_post_same_snapshot_rejected(self):
        response = self.client.post(self.url, {
            "base_snapshot": self.snap1.pk,
            "target_snapshot": self.snap1.pk,
        })
        self.assertEqual(ConfigComparison.objects.count(), 0)

    def test_compare_post_missing_selection(self):
        response = self.client.post(self.url, {
            "base_snapshot": "",
            "target_snapshot": "",
        })
        self.assertEqual(ConfigComparison.objects.count(), 0)
        self.assertContains(response, "Selecione dois snapshots")

    def test_compare_insufficient_snapshots_message(self):
        Device.objects.create(name="single-snap-d")
        snap_single = ConfigSnapshot.objects.create(
            device=Device.objects.get(name="single-snap-d"),
            raw_config="hostname X\n"
        )
        url_single = reverse("device_compare", args=[snap_single.device.pk])
        response = self.client.get(url_single)
        self.assertContains(response, "pelo menos 2 snapshots")

    def test_compare_404(self):
        response = self.client.get(reverse("device_compare", args=[9999]))
        self.assertEqual(response.status_code, 404)

    def test_compare_reuses_existing_comparison(self):
        comp = ConfigComparison.objects.create(
            base_snapshot=self.snap1,
            target_snapshot=self.snap2,
            title="Existing",
        )
        response = self.client.post(self.url, {
            "base_snapshot": self.snap1.pk,
            "target_snapshot": self.snap2.pk,
        })
        # Should redirect to existing comparison, not create new
        self.assertEqual(ConfigComparison.objects.count(), 1)
        self.assertRedirects(
            response, reverse("comparison_detail", args=[comp.pk])
        )


class DashboardViewTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(name="dash-test-device")
        self.user = User.objects.create_user(username="viewer4", password="viewer123")
        self.client.login(username="viewer4", password="viewer123")

    def test_dashboard_status(self):
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)

    def test_dashboard_contains_summary(self):
        response = self.client.get(reverse("dashboard"))
        self.assertContains(response, "Dispositivos")
        self.assertContains(response, "Snapshots")
        self.assertContains(response, "Análises")

    def test_dashboard_new_cards(self):
        response = self.client.get(reverse("dashboard"))
        # Check new context variables are present
        self.assertIn("vendor_summary", response.context)
        self.assertIn("top_issues_devices", response.context)
        self.assertIn("snapshots_7d", response.context)
        self.assertIn("devices_without_snapshot", response.context)
        self.assertIn("vendors_count", response.context)

    def test_dashboard_shows_fabricantes(self):
        Device.objects.create(name="cisco-dev", vendor="cisco")
        response = self.client.get(reverse("dashboard"))
        self.assertContains(response, "Fabricantes")
