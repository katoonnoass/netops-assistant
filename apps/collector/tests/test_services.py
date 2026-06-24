from django.test import TestCase

from apps.collector.discovery import MockSnmpAdapter, SnmpDiscoveryResult
from apps.collector.models import CollectorRun, CollectorTask, DiscoveryProfile
from apps.collector.services import run_discovery, run_collection


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
            subnets=["10.0.0.0/24"],
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
