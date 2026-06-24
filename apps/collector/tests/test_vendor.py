from django.test import SimpleTestCase

from apps.collector.vendor import (
    UNKNOWN_VENDOR,
    detect_vendor_from_sysdescr,
    get_collect_command,
    get_netmiko_device_type,
    is_supported_vendor,
)


class VendorDetectionTests(SimpleTestCase):
    def test_detect_huawei_by_vrp(self):
        result = detect_vendor_from_sysdescr("Huawei Versatile Routing Platform Software VRP (R) V800R012C00")
        self.assertEqual(result, "huawei")

    def test_detect_huawei_by_quidway(self):
        result = detect_vendor_from_sysdescr("Quidway S5700-28C-HI")
        self.assertEqual(result, "huawei")

    def test_detect_cisco_by_ios(self):
        result = detect_vendor_from_sysdescr("Cisco IOS-XE Software, Version 17.3.1a")
        self.assertEqual(result, "cisco")

    def test_detect_cisco_by_cisco(self):
        result = detect_vendor_from_sysdescr("Cisco NX-OS(tm) n9500")
        self.assertEqual(result, "cisco")

    def test_detect_zte(self):
        result = detect_vendor_from_sysdescr("ZTE ZXR10 5960-52TM")
        self.assertEqual(result, "zte")

    def test_detect_zte_by_c300(self):
        result = detect_vendor_from_sysdescr("ZTE ZXA10 C300")
        self.assertEqual(result, "zte")

    def test_detect_unknown_string(self):
        result = detect_vendor_from_sysdescr("Some random device description")
        self.assertEqual(result, UNKNOWN_VENDOR)

    def test_detect_none_input(self):
        result = detect_vendor_from_sysdescr(None)
        self.assertEqual(result, UNKNOWN_VENDOR)

    def test_detect_empty_input(self):
        result = detect_vendor_from_sysdescr("")
        self.assertEqual(result, UNKNOWN_VENDOR)

    def test_detect_by_sysobjectid(self):
        result = detect_vendor_from_sysdescr(None, "1.3.6.1.4.1.2011.1")
        self.assertEqual(result, "huawei")


class VendorMappingTests(SimpleTestCase):
    def test_huawei_netmiko_type(self):
        self.assertEqual(get_netmiko_device_type("huawei"), "huawei")

    def test_cisco_netmiko_type(self):
        self.assertEqual(get_netmiko_device_type("cisco"), "cisco_ios")

    def test_zte_netmiko_type(self):
        self.assertEqual(get_netmiko_device_type("zte"), "zte_zxros")

    def test_unknown_vendor_netmiko_type(self):
        self.assertIsNone(get_netmiko_device_type("unknown"))

    def test_huawei_collect_command(self):
        self.assertEqual(get_collect_command("huawei"), "display current-configuration")

    def test_cisco_collect_command(self):
        self.assertEqual(get_collect_command("cisco"), "show running-config")

    def test_unknown_vendor_collect_command(self):
        self.assertIsNone(get_collect_command("unknown"))

    def test_is_supported_huawei(self):
        self.assertTrue(is_supported_vendor("huawei"))

    def test_is_supported_cisco(self):
        self.assertTrue(is_supported_vendor("cisco"))

    def test_is_supported_zte(self):
        self.assertTrue(is_supported_vendor("zte"))

    def test_is_supported_unknown(self):
        self.assertFalse(is_supported_vendor("unknown"))
