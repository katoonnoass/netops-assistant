from unittest.mock import patch

from django.test import SimpleTestCase

from apps.collector.ssh_collector import RealSshCollectorAdapter
from apps.devices.models import Device


class RealSshCollectorAdapterExistsTests(SimpleTestCase):
    def test_adapter_can_be_instantiated(self):
        adapter = RealSshCollectorAdapter()
        self.assertIsNotNone(adapter)

    def test_adapter_is_subclass(self):
        from apps.collector.ssh_collector import BaseSshCollectorAdapter
        self.assertTrue(issubclass(RealSshCollectorAdapter, BaseSshCollectorAdapter))


class StubCredential:
    def __init__(self, username="admin", password="", enable_secret="", snmp_community=""):
        self.username = username
        self.encrypted_password = password
        self.encrypted_enable_secret = enable_secret
        self.snmp_community = snmp_community


class StubDevice:
    def __init__(self, name="test-device", vendor="huawei", ip_address="10.0.0.1", ssh_port=22):
        self.name = name
        self.vendor = vendor
        self.ip_address = ip_address
        self.ssh_port = ssh_port


@patch("apps.collector.ssh_collector.decrypt_value")
class RealSshCollectorAdapterMockedTests(SimpleTestCase):
    def setUp(self):
        self.adapter = RealSshCollectorAdapter()

    def test_huawei_uses_correct_command(self, mock_decrypt):
        mock_decrypt.return_value = "secret123"
        device = StubDevice(name="PE-01", vendor="huawei", ip_address="10.0.0.1")
        cred = StubCredential(username="admin", password="encrypted:sekret")

        with patch("apps.collector.ssh_collector.ConnectHandler") as mock_conn:
            instance = mock_conn.return_value.__enter__.return_value
            instance.send_command.return_value = "#sysname PE-01\n#\nreturn"
            result = self.adapter.collect_config(device, cred, timeout=10)

        self.assertTrue(result.success)
        self.assertEqual(result.command, "display current-configuration")
        mock_conn.assert_called_once()
        kwargs = mock_conn.call_args[1]
        self.assertEqual(kwargs["device_type"], "huawei")
        self.assertEqual(kwargs["host"], "10.0.0.1")
        self.assertEqual(kwargs["username"], "admin")
        self.assertEqual(kwargs["port"], 22)

    def test_cisco_uses_correct_command(self, mock_decrypt):
        mock_decrypt.return_value = "secret123"
        device = StubDevice(name="CORE-SW", vendor="cisco", ip_address="10.0.0.2")
        cred = StubCredential(username="admin", password="encrypted:sekret")

        with patch("apps.collector.ssh_collector.ConnectHandler") as mock_conn:
            instance = mock_conn.return_value.__enter__.return_value
            instance.send_command.return_value = "!running-config\nhostname CORE-SW\nend"
            result = self.adapter.collect_config(device, cred, timeout=10)

        self.assertTrue(result.success)
        self.assertEqual(result.command, "show running-config")
        kwargs = mock_conn.call_args[1]
        self.assertEqual(kwargs["device_type"], "cisco_ios")

    def test_unsupported_vendor_returns_error(self, mock_decrypt):
        device = StubDevice(name="Unknown", vendor="unknown", ip_address="10.0.0.3")
        cred = StubCredential(username="admin", password="sekret")
        result = self.adapter.collect_config(device, cred, timeout=10)
        self.assertFalse(result.success)
        self.assertIn("não suportado", result.error)

    def test_no_credential_returns_error(self, mock_decrypt):
        device = StubDevice(name="PE-01", vendor="huawei", ip_address="10.0.0.1")
        result = self.adapter.collect_config(device, None, timeout=10)
        self.assertFalse(result.success)
        self.assertIn("Nenhuma credencial", result.error)

    def test_no_username_returns_error(self, mock_decrypt):
        device = StubDevice(name="PE-01", vendor="huawei", ip_address="10.0.0.1")
        cred = StubCredential(username="", password="sekret")
        result = self.adapter.collect_config(device, cred, timeout=10)
        self.assertFalse(result.success)
        self.assertIn("Credencial sem usuário", result.error)

    def test_no_password_returns_error(self, mock_decrypt):
        mock_decrypt.return_value = ""
        device = StubDevice(name="PE-01", vendor="huawei", ip_address="10.0.0.1")
        cred = StubCredential(username="admin", password="")
        result = self.adapter.collect_config(device, cred, timeout=10)
        self.assertFalse(result.success)
        self.assertIn("senha", result.error)

    def test_no_ip_returns_error(self, mock_decrypt):
        device = StubDevice(name="PE-01", vendor="huawei", ip_address="")
        cred = StubCredential(username="admin", password="encrypted:sekret")
        result = self.adapter.collect_config(device, cred, timeout=10)
        self.assertFalse(result.success)
        self.assertIn("endereço IP", result.error)

    def test_netmiko_exception_returns_failed(self, mock_decrypt):
        mock_decrypt.return_value = "secret123"
        device = StubDevice(name="PE-01", vendor="huawei", ip_address="10.0.0.1")
        cred = StubCredential(username="admin", password="encrypted:sekret")

        with patch("apps.collector.ssh_collector.ConnectHandler", side_effect=ConnectionError("SSH connection refused")):
            result = self.adapter.collect_config(device, cred, timeout=10)

        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)

    def test_error_does_not_contain_password(self, mock_decrypt):
        mock_decrypt.return_value = "supersecret"
        device = StubDevice(name="PE-01", vendor="huawei", ip_address="10.0.0.1")
        cred = StubCredential(username="admin", password="encrypted:sekret")

        with patch("apps.collector.ssh_collector.ConnectHandler", side_effect=ConnectionError("supersecret")):
            result = self.adapter.collect_config(device, cred, timeout=10)

        self.assertFalse(result.success)
        self.assertNotIn("supersecret", result.error)

    def test_enable_secret_is_used(self, mock_decrypt):
        def side_effect(val):
            if val == "encrypted:sekret":
                return "realpassword"
            if val == "encrypted:enable":
                return "realsecret"
            return ""
        mock_decrypt.side_effect = side_effect

        device = StubDevice(name="CORE-SW", vendor="cisco", ip_address="10.0.0.2")
        cred = StubCredential(username="admin", password="encrypted:sekret", enable_secret="encrypted:enable")

        with patch("apps.collector.ssh_collector.ConnectHandler") as mock_conn:
            instance = mock_conn.return_value.__enter__.return_value
            instance.send_command.return_value = "!running"
            instance.enable.return_value = None
            result = self.adapter.collect_config(device, cred, timeout=10)

        self.assertTrue(result.success)
        kwargs = mock_conn.call_args[1]
        self.assertEqual(kwargs["secret"], "realsecret")
