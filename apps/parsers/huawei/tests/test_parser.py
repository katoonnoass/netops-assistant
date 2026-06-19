"""Tests for the Huawei VRP configuration parser."""

from pathlib import Path

from django.test import TestCase

from apps.parsers.huawei import HuaweiVRPParser

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class HuaweiVRPParserTest(TestCase):
    """Test suite for HuaweiVRPParser."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        fixture_path = FIXTURES_DIR / "sample_config.txt"
        with open(fixture_path, encoding="utf-8") as f:
            cls.sample_config = f.read()
        cls.parser = HuaweiVRPParser(cls.sample_config)
        cls.result = cls.parser.parse()

    def test_vendor_is_huawei(self):
        """Parser returns vendor as 'huawei'."""
        self.assertEqual(self.result["vendor"], "huawei")

    def test_sysname_extracted(self):
        """Parser correctly extracts the device sysname."""
        self.assertEqual(self.result["sysname"], "RACK01-CORE-SW01")

    def test_raw_text_preserved(self):
        """Parser preserves the original raw text."""
        self.assertEqual(self.result["raw"], self.sample_config)

    def test_blocks_detected(self):
        """Parser detects blocks in the configuration."""
        self.assertGreater(self.result["block_count"], 0)

    def test_interfaces_found(self):
        """Parser identifies interface blocks."""
        interfaces = self.result["interfaces"]
        self.assertGreater(len(interfaces), 0)

    def test_physical_interface_detected(self):
        """Parser detects physical interface GigabitEthernet0/0/1."""
        names = [iface["name"] for iface in self.result["interfaces"]]
        self.assertIn("GigabitEthernet0/0/1", names)

    def test_eth_trunk_detected(self):
        """Parser detects Eth-Trunk1."""
        names = [iface["name"] for iface in self.result["interfaces"]]
        self.assertIn("Eth-Trunk1", names)

    def test_subinterface_dot1q_detected(self):
        """Parser detects subinterface with dot1q VLAN."""
        subifaces = [
            iface
            for iface in self.result["interfaces"]
            if iface["subinterface_number"] is not None
        ]
        self.assertGreater(len(subifaces), 0)
        # Look for our known subinterface
        gig_sub = next(
            (
                i
                for i in self.result["interfaces"]
                if i["name"] == "GigabitEthernet0/0/1.100"
            ),
            None,
        )
        self.assertIsNotNone(gig_sub)
        self.assertEqual(gig_sub["vlan_type"], "dot1q")
        self.assertEqual(gig_sub["vlan_id"], "100")

    def test_interface_ip_address_extracted(self):
        """Parser extracts IP address from interfaces."""
        gig_sub = next(
            (
                i
                for i in self.result["interfaces"]
                if i["name"] == "GigabitEthernet0/0/1.100"
            ),
            None,
        )
        self.assertIsNotNone(gig_sub)
        self.assertEqual(gig_sub["ip_address"], "192.168.100.1 255.255.255.252")

    def test_loopback_detected(self):
        """Parser detects LoopBack interface."""
        names = [iface["name"] for iface in self.result["interfaces"]]
        self.assertIn("LoopBack0", names)

    def test_vlanif_detected(self):
        """Parser detects VLANIF interface."""
        names = [iface["name"] for iface in self.result["interfaces"]]
        self.assertIn("VLANIF10", names)

    def test_bgp_blocks_found(self):
        """Parser identifies BGP blocks."""
        self.assertGreater(len(self.result["bgp"]), 0)

    def test_bgp_as_number(self):
        """Parser extracts BGP AS number."""
        self.assertEqual(self.result["bgp"][0]["as_number"], "65000")

    def test_bgp_peers_detected(self):
        """Parser extracts BGP peers."""
        peers = self.result["bgp"][0]["peers"]
        self.assertGreater(len(peers), 0)
        peer_ips = [p["ip"] for p in peers]
        self.assertIn("10.200.0.2", peer_ips)
        self.assertIn("192.168.255.1", peer_ips)

    def test_bgp_networks_detected(self):
        """Parser extracts BGP network advertisements."""
        networks = self.result["bgp"][0]["networks"]
        self.assertGreater(len(networks), 0)

    def test_static_routes_found(self):
        """Parser identifies ip route-static commands."""
        self.assertGreater(len(self.result["static_routes"]), 0)

    def test_static_route_default(self):
        """Parser extracts default route."""
        routes = self.result["static_routes"]
        default = next(
            (r for r in routes if r.get("network") == "0.0.0.0"), None
        )
        self.assertIsNotNone(default)
        self.assertEqual(default["next_hop"], "10.200.0.2")

    def test_static_route_preference(self):
        """Parser extracts route preference."""
        routes = self.result["static_routes"]
        pref_route = next(
            (r for r in routes if r.get("preference") == "60"), None
        )
        self.assertIsNotNone(pref_route)
        self.assertEqual(pref_route["network"], "172.16.0.0")

    def test_static_route_tag(self):
        """Parser extracts route tag."""
        routes = self.result["static_routes"]
        tagged = next(
            (r for r in routes if r.get("tag") == "100"), None
        )
        self.assertIsNotNone(tagged)
        self.assertEqual(tagged["preference"], "5")

    def test_interface_type_physical(self):
        """Parser classifies physical interfaces correctly."""
        gig = next(
            (
                i
                for i in self.result["interfaces"]
                if i["name"] == "GigabitEthernet0/0/1"
            ),
            None,
        )
        self.assertIsNotNone(gig)
        self.assertEqual(gig["type"], "physical")

    def test_interface_type_eth_trunk(self):
        """Parser classifies Eth-Trunk correctly."""
        eth = next(
            (
                i
                for i in self.result["interfaces"]
                if i["name"] == "Eth-Trunk1"
            ),
            None,
        )
        self.assertIsNotNone(eth)
        self.assertEqual(eth["type"], "eth-trunk")

    def test_interface_type_subinterface(self):
        """Parser classifies subinterfaces correctly."""
        sub = next(
            (
                i
                for i in self.result["interfaces"]
                if i["name"] == "GigabitEthernet0/0/1.100"
            ),
            None,
        )
        self.assertIsNotNone(sub)
        self.assertEqual(sub["type"], "physical_subinterface")

    def test_eth_trunk_subinterface_type(self):
        """Parser classifies Eth-Trunk subinterface correctly."""
        sub = next(
            (
                i
                for i in self.result["interfaces"]
                if i["name"] == "Eth-Trunk1.200"
            ),
            None,
        )
        self.assertIsNotNone(sub)
        # Eth-Trunk subinterface
        self.assertEqual(sub["parent"], "Eth-Trunk1")
        self.assertEqual(sub["subinterface_number"], 200)

    def test_empty_config(self):
        """Parser handles empty config gracefully."""
        empty_parser = HuaweiVRPParser("")
        result = empty_parser.parse()
        self.assertEqual(result["vendor"], "huawei")
        self.assertEqual(result["sysname"], "")
        self.assertEqual(result["block_count"], 0)
        self.assertEqual(len(result["interfaces"]), 0)
        self.assertEqual(len(result["bgp"]), 0)
        self.assertEqual(len(result["static_routes"]), 0)

    def test_interface_description(self):
        """Parser extracts interface description."""
        gig = next(
            (
                i
                for i in self.result["interfaces"]
                if i["name"] == "GigabitEthernet0/0/1"
            ),
            None,
        )
        self.assertIsNotNone(gig)
        self.assertEqual(gig["description"], "LINK-FIBRA-CLIENTE-A")
