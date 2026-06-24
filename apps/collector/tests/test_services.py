from django.test import TestCase

from apps.collector.discovery import MockSnmpAdapter, SnmpDiscoveryResult
from apps.collector.models import CollectorRun, CollectorTask, DiscoveryProfile
from apps.collector.services import run_discovery, run_collection
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
        result = run_discovery(profile=self.profile, dry_run=True)
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
        run = run_discovery(profile=self.profile, adapter=self.adapter)
        device = Device.objects.filter(name="PE-01").first()
        self.assertIsNotNone(device)
        self.assertEqual(device.ip_address, "10.0.0.1")
        self.assertEqual(device.vendor, "huawei")

    def test_discovery_updates_last_discovered_at(self):
        run = run_discovery(profile=self.profile, adapter=self.adapter)
        device = Device.objects.get(name="PE-01")
        self.assertIsNotNone(device.last_discovered_at)

    def test_does_not_duplicate_device_by_ip(self):
        Device.objects.create(name="Existing", ip_address="10.0.0.1", vendor="huawei")
        run = run_discovery(profile=self.profile, adapter=self.adapter)
        count = Device.objects.filter(ip_address="10.0.0.1").count()
        self.assertEqual(count, 1)

    def test_does_not_duplicate_device_by_name(self):
        Device.objects.create(name="PE-01", vendor="huawei")
        run = run_discovery(profile=self.profile, adapter=self.adapter)
        count = Device.objects.filter(name="PE-01").count()
        self.assertEqual(count, 1)

    def test_summary_counts_in_run(self):
        run = run_discovery(profile=self.profile, adapter=self.adapter)
        self.assertIn("Escaneados", run.summary)
        self.assertIn("Descobertos", run.summary)

    def test_discovery_with_allow_large_subnet(self):
        profile = DiscoveryProfile.objects.create(
            name="Large Subnet",
            subnets=["10.0.0.0/23"],
            snmp_community="public",
            is_active=True,
        )
        run = run_discovery(profile=profile, adapter=self.adapter, allow_large_subnet=True)
        # Should not raise, even with /23
        self.assertIsNotNone(run.pk)


class RunCollectionDryRunTests(TestCase):
    def setUp(self):
        self.profile = DiscoveryProfile.objects.create(
            name="Collector Test",
            subnets=["10.0.0.0/24"],
            is_active=True,
        )

    def test_dry_run_returns_lines(self):
        result = run_collection(profile=self.profile, dry_run=True)
        self.assertTrue(any("DRY-RUN" in line for line in result))

    def test_dry_run_does_not_create_run(self):
        run_collection(profile=self.profile, dry_run=True)
        self.assertEqual(CollectorRun.objects.count(), 0)

    def test_requires_profile_or_device(self):
        with self.assertRaises(ValueError):
            run_collection()
