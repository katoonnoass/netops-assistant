from django.test import TestCase

from ..lldp_parser import (
    normalize_interface_name,
    parse_adjacency_csv,
    parse_cisco_lldp_neighbors,
    parse_generic_lldp_table,
    parse_huawei_lldp_brief,
    parse_lldp_neighbors,
)

HUAWEI_LLDP = """Local Interface    Exptime(s)    Neighbor Interface    Neighbor Device
GE0/0/1            120           GE0/0/2               SW-02
XGE0/0/1           107           XGE0/0/2              CORE-01
Eth-Trunk10        100           Eth-Trunk20           PE-01
"""

CISCO_LLDP = """Device ID           Local Intf     Hold-time  Capability      Port ID
SW-02               Gi0/1          120        B,R             Gi0/2
CORE-01             Te1/0/1        120        R               Te1/0/2
"""

GENERIC_LLDP = """GE0/0/1            GE0/0/2            SW-02
XGE0/0/1           XGE0/0/2           CORE-01
"""

INVALID_LLDP = """Some random text
that is not LLDP
"""

GOOD_CSV = """local_device,local_interface,remote_device,remote_interface,method,confidence
SW-01,GigabitEthernet0/0/1,SW-02,GigabitEthernet0/0/2,manual,high
SW-02,XGigabitEthernet0/0/1,PE-01,Eth-Trunk100,manual,high
"""

CSV_MISSING_FIELDS = """local_device,local_interface,remote_device,remote_interface
SW-01,GigabitEthernet0/0/1
"""

CSV_NO_HEADER = """SW-01,GE0/0/1,SW-02,GE0/0/2,manual,high
SW-02,XGE0/0/1,PE-01,Eth-Trunk100,manual,low
"""


class HuaweiLldpParserTests(TestCase):
    def test_parse_huawei_lldp(self):
        result = parse_huawei_lldp_brief(HUAWEI_LLDP)
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]["local_interface"], "GE0/0/1")
        self.assertEqual(result[0]["remote_device"], "SW-02")
        self.assertEqual(result[0]["remote_interface"], "GE0/0/2")
        self.assertEqual(result[0]["holdtime"], 120)

    def test_parse_huawei_with_xge(self):
        result = parse_huawei_lldp_brief(HUAWEI_LLDP)
        xe = [r for r in result if r["local_interface"] == "XGE0/0/1"]
        self.assertEqual(len(xe), 1)
        self.assertEqual(xe[0]["remote_device"], "CORE-01")

    def test_parse_huawei_with_ethtrunk(self):
        result = parse_huawei_lldp_brief(HUAWEI_LLDP)
        et = [r for r in result if r["local_interface"] == "Eth-Trunk10"]
        self.assertEqual(len(et), 1)
        self.assertEqual(et[0]["remote_interface"], "Eth-Trunk20")

    def test_parse_huawei_empty(self):
        result = parse_huawei_lldp_brief("")
        self.assertEqual(result, [])

    def test_parse_huawei_no_header(self):
        result = parse_huawei_lldp_brief("GE0/0/1  120  GE0/0/2  SW-02")
        self.assertEqual(len(result), 0)


class CiscoLldpParserTests(TestCase):
    def test_parse_cisco_lldp(self):
        result = parse_cisco_lldp_neighbors(CISCO_LLDP)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["remote_device"], "SW-02")
        self.assertEqual(result[0]["local_interface"], "Gi0/1")
        self.assertEqual(result[0]["remote_interface"], "Gi0/2")
        self.assertEqual(result[0]["capability"], "B,R")

    def test_parse_cisco_empty(self):
        result = parse_cisco_lldp_neighbors("")
        self.assertEqual(result, [])

    def test_parse_cisco_invalid_lines_ignored(self):
        result = parse_cisco_lldp_neighbors(f"Device ID           Local Intf     Hold-time  Capability      Port ID\n{'-'*60}\nINVALID\n")
        self.assertEqual(len(result), 0)


class GenericLldpParserTests(TestCase):
    def test_parse_generic(self):
        result = parse_generic_lldp_table(GENERIC_LLDP)
        self.assertEqual(len(result), 2)

    def test_parse_generic_empty(self):
        result = parse_generic_lldp_table("")
        self.assertEqual(result, [])

    def test_parse_generic_separator_line(self):
        text = "GE0/0/1    GE0/0/2    SW-02\n---------\nXGE0/0/1   XGE0/0/2   CORE-01\n"
        result = parse_generic_lldp_table(text)
        self.assertEqual(len(result), 2)


class LldpAutoDetectTests(TestCase):
    def test_detect_huawei(self):
        result = parse_lldp_neighbors(HUAWEI_LLDP)
        self.assertEqual(len(result), 3)

    def test_detect_cisco(self):
        result = parse_lldp_neighbors(CISCO_LLDP)
        self.assertEqual(len(result), 2)

    def test_detect_generic(self):
        result = parse_lldp_neighbors(GENERIC_LLDP)
        self.assertEqual(len(result), 2)

    def test_detect_empty(self):
        result = parse_lldp_neighbors("")
        self.assertEqual(result, [])

    def test_vendor_hint_huawei(self):
        result = parse_lldp_neighbors(HUAWEI_LLDP, vendor="huawei")
        self.assertEqual(len(result), 3)

    def test_vendor_hint_cisco(self):
        result = parse_lldp_neighbors(CISCO_LLDP, vendor="cisco")
        self.assertEqual(len(result), 2)


class NormalizeInterfaceTests(TestCase):
    def test_gigabit_ethernet(self):
        self.assertEqual(normalize_interface_name("GigabitEthernet0/0/1"), "GE0/0/1")

    def test_xgigabit_ethernet(self):
        self.assertEqual(normalize_interface_name("XGigabitEthernet0/0/1"), "XGE0/0/1")

    def test_fast_ethernet(self):
        self.assertEqual(normalize_interface_name("FastEthernet0/1"), "FE0/1")

    def test_eth_trunk(self):
        self.assertEqual(normalize_interface_name("Eth-Trunk10"), "Eth-Trunk10")

    def test_loopback(self):
        self.assertEqual(normalize_interface_name("LoopBack0"), "LoopBack0")

    def test_vlanif(self):
        self.assertEqual(normalize_interface_name("Vlanif100"), "Vlanif100")

    def test_already_short(self):
        self.assertEqual(normalize_interface_name("GE0/0/1"), "GE0/0/1")

    def test_empty(self):
        self.assertEqual(normalize_interface_name(""), "")
        self.assertIsNone(normalize_interface_name(None))


class CsvParserTests(TestCase):
    def test_parse_valid_csv(self):
        result = parse_adjacency_csv(GOOD_CSV)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["local_device"], "SW-01")
        self.assertEqual(result[0]["remote_interface"], "GE0/0/2")
        self.assertEqual(result[0]["method"], "manual")
        self.assertEqual(result[0]["confidence"], "high")

    def test_csv_with_missing_fields(self):
        result = parse_adjacency_csv(CSV_MISSING_FIELDS)
        errors = [r for r in result if "error" in r]
        self.assertGreater(len(errors), 0)

    def test_csv_without_header_uses_defaults(self):
        result = parse_adjacency_csv("SW-01,GE0/0/1,SW-02,GE0/0/2,manual,high\n")
        self.assertEqual(len(result), 0)

    def test_csv_empty(self):
        result = parse_adjacency_csv("")
        self.assertEqual(len(result), 0)

    def test_csv_invalid_method_defaults(self):
        csv_text = "local_device,local_interface,remote_device,remote_interface,method,confidence\nSW-01,GE0/0/1,SW-02,GE0/0/2,unknown,invalid\n"
        result = parse_adjacency_csv(csv_text)
        self.assertEqual(result[0]["method"], "manual")
        self.assertEqual(result[0]["confidence"], "high")
