from unittest.mock import patch

from django.test import SimpleTestCase

from apps.collector.discovery import RealSnmpAdapter, SnmpDiscoveryResult


class RealSnmpAdapterExistsTests(SimpleTestCase):
    def test_adapter_can_be_instantiated(self):
        adapter = RealSnmpAdapter()
        self.assertIsNotNone(adapter)

    def test_adapter_is_instance(self):
        from apps.collector.discovery import BaseSnmpAdapter
        self.assertTrue(issubclass(RealSnmpAdapter, BaseSnmpAdapter))


@patch("apps.collector.discovery._snmp_get")
class RealSnmpAdapterMockedTests(SimpleTestCase):
    def setUp(self):
        self.adapter = RealSnmpAdapter()

    def test_returns_success_when_pysnmp_returns_data(self, mock_get):
        def side_effect(ip, oid, community, timeout):
            if "1.1.1.0" in oid:
                return "Huawei VRP"
            if "1.1.2.0" in oid:
                return "1.3.6.1.4.1.2011.1"
            if "1.1.5.0" in oid:
                return "PE-01"
            return None

        mock_get.side_effect = side_effect

        result = self.adapter.get_system_info("10.0.0.1", community="public")
        self.assertTrue(result.success)
        self.assertEqual(result.sys_name, "PE-01")
        self.assertEqual(result.sys_descr, "Huawei VRP")
        self.assertEqual(result.sys_object_id, "1.3.6.1.4.1.2011.1")
        self.assertEqual(result.vendor, "huawei")

    def test_returns_failed_when_pysnmp_raises(self, mock_get):
        mock_get.side_effect = ConnectionError("SNMP timeout")

        result = self.adapter.get_system_info("10.0.0.1", community="public")
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)

    def test_error_does_not_contain_community(self, mock_get):
        mock_get.side_effect = ConnectionError("SNMP timeout public")
        result = self.adapter.get_system_info("10.0.0.1", community="secretcommunity")
        # Ensure community is masked in error
        self.assertNotIn("secretcommunity", result.error)

    def test_no_response_when_all_none(self, mock_get):
        mock_get.return_value = None
        result = self.adapter.get_system_info("10.0.0.1", community="public")
        self.assertFalse(result.success)
        self.assertEqual(result.error, "Sem resposta SNMP (timeout ou comunidade inválida)")

    def test_unsupported_version(self, mock_get):
        result = self.adapter.get_system_info("10.0.0.1", community="public", version="v3")
        self.assertFalse(result.success)
        self.assertIn("não suportada", result.error)

    def test_empty_community(self, mock_get):
        result = self.adapter.get_system_info("10.0.0.1", community="")
        self.assertFalse(result.success)
        self.assertIn("community não configurada", result.error)
        mock_get.assert_not_called()
