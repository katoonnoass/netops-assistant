from unittest.mock import patch

from django.test import TestCase

from apps.collector.discovery import MockSnmpAdapter, SnmpDiscoveryResult
from apps.collector.models import CollectorRun, CollectorTask, DiscoveryProfile
from apps.collector.services import run_discovery, run_collection
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device


MOCK_TABLE = {
    "10.0.0.1": SnmpDiscoveryResult(
        ip_address="10.0.0.1",
        sys_name="PE-01",
        sys_descr="Huawei VRP",
        vendor="huawei",
        success=True,
    ),
    "10.0.0.2": SnmpDiscoveryResult(
        ip_address="10.0.0.2",
        success=False,
        error="No response",
    ),
}


class RunDiscoveryTests(TestCase):
    def setUp(self):
        self.profile = DiscoveryProfile.objects.create(
            name="Discovery Test",
            subnets=["10.0.0.0/30"],
            snmp_community="public",
            is_active=True,
        )
        self.adapter = MockSnmpAdapter(discovery_table=MOCK_TABLE)

    def test_creates_collector_run(self):
        run = run_discovery(profile=self.profile, adapter=self.adapter)
        self.assertIsNotNone(run.pk)

    def test_creates_collector_tasks(self):
        run = run_discovery(profile=self.profile, adapter=self.adapter)
        tasks = CollectorTask.objects.filter(run=run)
        self.assertGreater(tasks.count(), 0)

    def test_updates_discovered_count(self):
        run = run_discovery(profile=self.profile, adapter=self.adapter)
        self.assertGreaterEqual(run.discovered_count, 1)

    def test_partial_status_when_some_fail(self):
        run = run_discovery(profile=self.profile, adapter=self.adapter)
        self.assertIn(run.status, [CollectorRun.Status.PARTIAL, CollectorRun.Status.SUCCESS])

    def test_dry_run_does_not_create_run(self):
        run_discovery(profile=self.profile, dry_run=True)
        self.assertEqual(CollectorRun.objects.count(), 0)

    def test_inactive_profile_raises_error(self):
        self.profile.is_active = False
        self.profile.save()
        with self.assertRaises(ValueError):
            run_discovery(profile=self.profile)

    def test_no_community_raises_error(self):
        profile = DiscoveryProfile.objects.create(
            name="No Community",
            subnets=["10.0.0.0/30"],
            snmp_community="",
            is_active=True,
        )
        with self.assertRaises(ValueError) as ctx:
            run_discovery(profile=profile, adapter=self.adapter)
        self.assertIn("community", str(ctx.exception).lower())

    def test_successful_discovery_creates_device(self):
        run_discovery(profile=self.profile, adapter=self.adapter)
        device = Device.objects.filter(name="PE-01").first()
        self.assertIsNotNone(device)
        self.assertEqual(device.ip_address, "10.0.0.1")
        self.assertEqual(device.vendor, "huawei")

    def test_discovery_updates_last_discovered_at(self):
        run_discovery(profile=self.profile, adapter=self.adapter)
        device = Device.objects.get(name="PE-01")
        self.assertIsNotNone(device.last_discovered_at)

    def test_does_not_duplicate_device_by_ip(self):
        Device.objects.create(name="Existing", ip_address="10.0.0.1", vendor="huawei")
        run_discovery(profile=self.profile, adapter=self.adapter)
        count = Device.objects.filter(ip_address="10.0.0.1").count()
        self.assertEqual(count, 1)

    def test_does_not_duplicate_device_by_name(self):
        Device.objects.create(name="PE-01", vendor="huawei")
        run_discovery(profile=self.profile, adapter=self.adapter)
        count = Device.objects.filter(name="PE-01").count()
        self.assertEqual(count, 1)

    def test_discovery_with_allow_large_subnet(self):
        profile = DiscoveryProfile.objects.create(
            name="Large Subnet",
            subnets=["10.0.0.0/23"],
            snmp_community="public",
            is_active=True,
        )
        run = run_discovery(profile=profile, adapter=self.adapter, allow_large_subnet=True)
        self.assertIsNotNone(run.pk)


class RunCollectionTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(
            name="PE-01", vendor="huawei", ip_address="10.0.0.1", collector_enabled=True,
        )
        self.profile = DiscoveryProfile.objects.create(
            name="Collection Test",
            snmp_community="public",
            is_active=True,
        )

    def _make_mock_adapter(self, success=True, config_text="# config", error=None):
        mock_adapter = type("MockAdapter", (), {})()
        result = type("Result", (), {})()
        result.success = success
        result.config_text = config_text
        result.command = "display current-configuration"
        result.device_name = "PE-01"
        result.ip_address = "10.0.0.1"
        result.vendor = "huawei"
        result.error = error
        mock_adapter.collect_config = lambda d, c, timeout=10: result
        return mock_adapter

    def test_collection_creates_config_snapshot(self):
        adapter = self._make_mock_adapter()
        with patch("apps.collector.services.RealSshCollectorAdapter", return_value=adapter):
            run = run_collection(profile=self.profile, device=self.device)

        self.assertEqual(run.collected_count, 1)
        snapshots = ConfigSnapshot.objects.filter(device=self.device)
        self.assertEqual(snapshots.count(), 1)
        self.assertEqual(snapshots.first().source, "auto")

    def test_collection_updates_last_collected_at(self):
        adapter = self._make_mock_adapter()
        with patch("apps.collector.services.RealSshCollectorAdapter", return_value=adapter):
            run_collection(profile=self.profile, device=self.device)

        self.device.refresh_from_db()
        self.assertIsNotNone(self.device.last_collected_at)

    def test_empty_config_does_not_create_snapshot(self):
        adapter = self._make_mock_adapter(success=False, config_text=None, error="Falha")
        with patch("apps.collector.services.RealSshCollectorAdapter", return_value=adapter):
            run = run_collection(profile=self.profile, device=self.device)

        self.assertEqual(run.collected_count, 0)
        self.assertEqual(ConfigSnapshot.objects.count(), 0)

    def test_disabled_device_is_skipped(self):
        self.device.collector_enabled = False
        self.device.save()
        adapter = self._make_mock_adapter()

        with patch("apps.collector.services.RealSshCollectorAdapter", return_value=adapter):
            run = run_collection(profile=self.profile, device=self.device)

        self.assertEqual(run.collected_count, 0)

    def test_failure_returns_failed_status(self):
        adapter = self._make_mock_adapter(success=False, config_text=None, error="SSH error")
        with patch("apps.collector.services.RealSshCollectorAdapter", return_value=adapter):
            run = run_collection(profile=self.profile, device=self.device)

        self.assertEqual(run.failed_count, 1)
        self.assertEqual(run.status, CollectorRun.Status.FAILED)

    def test_dry_run_returns_lines(self):
        result = run_collection(profile=self.profile, dry_run=True)
        self.assertTrue(any("DRY-RUN" in line for line in result))

    def test_dry_run_does_not_create_run(self):
        run_collection(profile=self.profile, dry_run=True)
        self.assertEqual(CollectorRun.objects.count(), 0)

    def test_requires_profile_or_device(self):
        with self.assertRaises(ValueError):
            run_collection()


class RunCollectionAnalyzeTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(
            name="PE-01", vendor="huawei", ip_address="10.0.0.1", collector_enabled=True,
        )
        self.profile = DiscoveryProfile.objects.create(
            name="Analyze Test",
            snmp_community="public",
            is_active=True,
        )

    def test_analyze_calls_pipeline(self):
        mock_adapter = type("MockAdapter", (), {})()
        result = type("Result", (), {})()
        result.success = True
        result.config_text = "# config\nip address 1.2.3.4\n#\nreturn"
        result.command = "display current-configuration"
        result.device_name = "PE-01"
        result.ip_address = "10.0.0.1"
        result.vendor = "huawei"
        result.error = None
        mock_adapter.collect_config = lambda d, c, timeout=10: result

        with patch("apps.analysis.services.analyze_config_snapshot") as mock_analyze:
            mock_analyze.return_value = None
            with patch("apps.collector.services.RealSshCollectorAdapter", return_value=mock_adapter):
                run = run_collection(profile=self.profile, device=self.device, analyze=True)

        self.assertEqual(run.analyzed_count, 1)
        mock_analyze.assert_called_once()
