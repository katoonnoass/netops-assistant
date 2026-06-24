from django.test import SimpleTestCase, TestCase

from apps.collector.discovery import MockSnmpAdapter, SnmpDiscoveryResult, expand_cidr, validate_subnet_size


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


class ExpandCidrTests(SimpleTestCase):
    def test_expand_24_returns_hosts(self):
        hosts = expand_cidr("10.0.0.0/24")
        self.assertEqual(len(hosts), 254)
        self.assertEqual(hosts[0], "10.0.0.1")
        self.assertEqual(hosts[-1], "10.0.0.254")

    def test_expand_30_returns_few_hosts(self):
        hosts = expand_cidr("10.0.0.0/30")
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0], "10.0.0.1")
        self.assertEqual(hosts[-1], "10.0.0.2")

    def test_expand_32_returns_single(self):
        hosts = expand_cidr("10.0.0.1/32")
        self.assertEqual(hosts, ["10.0.0.1"])

    def test_invalid_cidr_returns_bare_ip(self):
        # Without '/', it returns the input as-is
        self.assertEqual(expand_cidr("invalid"), ["invalid"])

    def test_empty_cidr_returns_empty(self):
        self.assertEqual(expand_cidr(""), [])


class ValidateSubnetSizeTests(SimpleTestCase):
    def test_24_allowed_by_default(self):
        self.assertTrue(validate_subnet_size("10.0.0.0/24"))

    def test_25_allowed(self):
        self.assertTrue(validate_subnet_size("10.0.0.0/25"))

    def test_23_raises_by_default(self):
        with self.assertRaises(ValueError) as ctx:
            validate_subnet_size("10.0.0.0/23")
        self.assertIn("23", str(ctx.exception))

    def test_23_allowed_with_flag(self):
        self.assertTrue(validate_subnet_size("10.0.0.0/23", allow_large=True))

    def test_16_allowed_with_flag(self):
        self.assertTrue(validate_subnet_size("10.0.0.0/16", allow_large=True))

    def test_16_raises_by_default(self):
        with self.assertRaises(ValueError):
            validate_subnet_size("10.0.0.0/16")


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



