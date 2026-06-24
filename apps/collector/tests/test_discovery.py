from django.test import TestCase

from apps.collector.discovery import (
    MockSnmpAdapter,
    SnmpDiscoveryResult,
    discover_subnet,
)
from apps.collector.models import DiscoveryProfile


MOCK_TABLE = {
    "10.0.0.1": SnmpDiscoveryResult(
        ip_address="10.0.0.1",
        sys_name="PE-01",
        sys_descr="Huawei VRP",
        sys_object_id="1.3.6.1.4.1.2011.1",
        vendor="huawei",
        success=True,
    ),
    "10.0.0.2": SnmpDiscoveryResult(
        ip_address="10.0.0.2",
        sys_name="CORE-SW-01",
        sys_descr="Cisco IOS",
        vendor="cisco",
        success=True,
    ),
    "10.0.0.3": SnmpDiscoveryResult(
        ip_address="10.0.0.3",
        success=False,
        error="No response",
    ),
}


class MockSnmpAdapterTests(TestCase):
    def setUp(self):
        self.adapter = MockSnmpAdapter(discovery_table=MOCK_TABLE)

    def test_returns_success_for_known_ip(self):
        result = self.adapter.get_system_info("10.0.0.1")
        self.assertTrue(result.success)
        self.assertEqual(result.sys_name, "PE-01")

    def test_returns_vendor_from_table(self):
        result = self.adapter.get_system_info("10.0.0.2")
        self.assertEqual(result.vendor, "cisco")

    def test_returns_failure_for_unknown_ip(self):
        result = self.adapter.get_system_info("10.0.0.99")
        self.assertFalse(result.success)
        self.assertIn("não encontrado", result.error)


class DiscoverSubnetDryRunTests(TestCase):
    def setUp(self):
        self.profile = DiscoveryProfile.objects.create(
            name="Test Profile",
            subnets=["10.0.0.0/24"],
            is_active=True,
        )

    def test_dry_run_returns_lines(self):
        result = discover_subnet(self.profile, dry_run=True)
        self.assertTrue(any("DRY-RUN" in line for line in result))

    def test_dry_run_does_not_touch_db(self):
        from apps.collector.models import CollectorRun
        discover_subnet(self.profile, dry_run=True)
        self.assertEqual(CollectorRun.objects.count(), 0)
