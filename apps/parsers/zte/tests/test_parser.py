from pathlib import Path

from django.test import TestCase

from apps.parsers.zte import ZTEOLTParser


def load_sample() -> str:
    path = Path(__file__).with_name("fixtures").joinpath("zte_olt_basic.txt")
    return path.read_text(encoding="utf-8")


class ZTEOLTParserTests(TestCase):
    def setUp(self):
        self.parsed = ZTEOLTParser(load_sample()).parse()

    def test_vendor_platform_and_hostname(self):
        self.assertEqual(self.parsed["vendor"], "zte")
        self.assertEqual(self.parsed["platform"], "zte_olt")
        self.assertEqual(self.parsed["hostname"], "ZTE-OLT-C320-01")

    def test_uplink_vlan_and_route(self):
        uplink = self.parsed["interfaces"][0]
        self.assertEqual(uplink["name"], "gei_1/4/1")
        self.assertEqual(uplink["type"], "uplink")
        self.assertEqual(uplink["ip_address"], "10.10.10.2/30")
        self.assertEqual(self.parsed["vlans"][0]["vlan_id"], "100")
        self.assertEqual(self.parsed["static_routes"][0]["next_hop"], "10.10.10.1")

    def test_pon_ports_and_onus(self):
        olt = self.parsed["zte_olt"]
        self.assertTrue(olt["enabled"])
        self.assertEqual(len(olt["pon_ports"]), 1)
        self.assertEqual(olt["pon_ports"][0]["pon"], "1/1/1")
        self.assertEqual(olt["pon_ports"][0]["onu_count"], 2)
        self.assertEqual(len(olt["onus"]), 2)
        self.assertEqual(olt["onus"][0]["serial"], "ZTEG12345678")
        self.assertEqual(olt["onus"][0]["description"], "CLIENTE-001")

    def test_onu_services(self):
        onu = self.parsed["zte_olt"]["onus"][0]
        self.assertEqual(onu["tconts"][0]["id"], "1")
        self.assertEqual(onu["gemports"][0]["id"], "1")
        self.assertTrue(any(service["vlan"] == "100" for service in onu["service_ports"]))
        self.assertTrue(any(service["onu"] == "gpon-onu_1/1/1:1" for service in self.parsed["zte_olt"]["service_ports"]))
