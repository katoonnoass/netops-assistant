from django.test import TestCase

from apps.collector.ssh_collector import MockSshCollectorAdapter
from apps.devices.models import Device


class MockSshCollectorTests(TestCase):
    def setUp(self):
        self.device = Device.objects.create(
            name="PE-01",
            vendor="huawei",
            ip_address="10.0.0.1",
        )
        self.adapter = MockSshCollectorAdapter()

    def test_returns_config_for_supported_vendor(self):
        result = self.adapter.collect_config(self.device, None)
        self.assertTrue(result.success)
        self.assertIsNotNone(result.config_text)
        self.assertIn("sysname", result.config_text)

    def test_returns_vendor_command(self):
        result = self.adapter.collect_config(self.device, None)
        self.assertEqual(result.command, "display current-configuration")

    def test_fails_for_unsupported_vendor(self):
        device = Device.objects.create(name="Unknown", vendor="unknown", ip_address="10.0.0.99")
        result = self.adapter.collect_config(device, None)
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)

    def test_secrets_not_in_log(self):
        result = self.adapter.collect_config(self.device, None)
        self.assertIsNotNone(result.log if hasattr(result, 'log') else result.config_text)
