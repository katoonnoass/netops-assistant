"""Tests for the Cisco IOS/IOS-XE configuration parser."""

from pathlib import Path

from django.test import TestCase

from apps.parsers.cisco import CiscoIOSParser

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class CiscoIOSParserTest(TestCase):
    """Test suite for CiscoIOSParser."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        fixture_path = FIXTURES_DIR / "sample_running_config.txt"
        with open(fixture_path, encoding="utf-8") as f:
            cls.sample_config = f.read()
        cls.parser = CiscoIOSParser(cls.sample_config)
        cls.result = cls.parser.parse()

    # ── Vendor / metadata ──────────────────────────────────────────────

    def test_vendor_is_cisco(self):
        """Parser returns vendor as 'cisco'."""
        self.assertEqual(self.result["vendor"], "cisco")

    def test_platform_is_ios(self):
        """Parser returns platform as 'ios'."""
        self.assertEqual(self.result["platform"], "ios")

    def test_hostname_extracted(self):
        """Parser correctly extracts the device hostname."""
        self.assertEqual(self.result["hostname"], "ROTEADOR-BORDA-SP")
        self.assertEqual(self.result["sysname"], "ROTEADOR-BORDA-SP")

    def test_raw_text_preserved(self):
        """Parser preserves the original raw text."""
        self.assertEqual(self.result["raw"], self.sample_config)

    def test_blocks_detected(self):
        """Parser detects blocks in the configuration."""
        self.assertGreater(self.result["block_count"], 0)

    # ── Interfaces ─────────────────────────────────────────────────────

    def test_interfaces_found(self):
        """Parser identifies interface blocks."""
        interfaces = self.result["interfaces"]
        self.assertGreater(len(interfaces), 0)

    def test_physical_interface_detected(self):
        """Parser detects physical interface GigabitEthernet0/0."""
        names = [iface["name"] for iface in self.result["interfaces"]]
        self.assertIn("GigabitEthernet0/0", names)

    def test_subinterface_dot1q_detected(self):
        """Parser detects subinterface with encapsulation dot1Q."""
        sub = next(
            (
                i
                for i in self.result["interfaces"]
                if i["name"] == "GigabitEthernet0/0.1234"
            ),
            None,
        )
        self.assertIsNotNone(sub)
        self.assertEqual(sub["vlan_type"], "dot1q")
        self.assertEqual(sub["vlan_id"], 1234)
        self.assertTrue(sub["has_dot1q"])
        self.assertEqual(sub["encapsulation"], "dot1q")

    def test_subinterface_ip_extracted(self):
        """Parser extracts IP address from subinterface."""
        sub = next(
            (
                i
                for i in self.result["interfaces"]
                if i["name"] == "GigabitEthernet0/0.1234"
            ),
            None,
        )
        self.assertIsNotNone(sub)
        self.assertEqual(sub["ip_address"], "10.255.123.1 255.255.255.252")
        self.assertTrue(sub["has_ip"])

    def test_subinterface_parent(self):
        """Parser extracts parent interface from subinterface."""
        sub = next(
            (
                i
                for i in self.result["interfaces"]
                if i["name"] == "GigabitEthernet0/0.1234"
            ),
            None,
        )
        self.assertIsNotNone(sub)
        self.assertEqual(sub["parent"], "GigabitEthernet0/0")
        self.assertEqual(sub["subinterface_number"], 1234)

    def test_interface_description(self):
        """Parser extracts interface description."""
        iface = next(
            (
                i
                for i in self.result["interfaces"]
                if i["name"] == "GigabitEthernet0/0"
            ),
            None,
        )
        self.assertIsNotNone(iface)
        self.assertEqual(iface["description"], "UPLINK-SP")

    def test_loopback_detected(self):
        """Parser detects Loopback interface."""
        names = [iface["name"] for iface in self.result["interfaces"]]
        self.assertIn("Loopback0", names)

    def test_interface_type_subinterface(self):
        """Parser classifies subinterfaces correctly."""
        sub = next(
            (
                i
                for i in self.result["interfaces"]
                if i["name"] == "GigabitEthernet0/0.1234"
            ),
            None,
        )
        self.assertIsNotNone(sub)
        self.assertEqual(sub["type"], "subinterface")

    def test_interface_type_loopback(self):
        """Parser classifies loopback correctly."""
        lb = next(
            (
                i
                for i in self.result["interfaces"]
                if i["name"] == "Loopback0"
            ),
            None,
        )
        self.assertIsNotNone(lb)
        self.assertEqual(lb["type"], "loopback")

    def test_interface_not_shutdown(self):
        """Parser extracts 'no shutdown' correctly."""
        iface = next(
            (
                i
                for i in self.result["interfaces"]
                if i["name"] == "GigabitEthernet0/0"
            ),
            None,
        )
        self.assertIsNotNone(iface)
        self.assertFalse(iface["shutdown"])

    def test_interface_without_description(self):
        """Parser handles interfaces without description."""
        iface = next(
            (
                i
                for i in self.result["interfaces"]
                if i["name"] == "GigabitEthernet0/1"
            ),
            None,
        )
        self.assertIsNotNone(iface)
        self.assertEqual(iface["description"], "")

    # ── Static routes ──────────────────────────────────────────────────

    def test_static_routes_found(self):
        """Parser identifies ip route commands."""
        routes = self.result["static_routes"]
        self.assertGreater(len(routes), 0)

    def test_static_route_specific(self):
        """Parser extracts specific static route."""
        routes = self.result["static_routes"]
        target = next(
            (r for r in routes if r.get("network") == "200.200.200.0"), None
        )
        self.assertIsNotNone(target)
        self.assertEqual(target["netmask"], "255.255.255.252")
        self.assertEqual(target["next_hop"], "10.255.123.2")

    def test_static_route_default(self):
        """Parser extracts default route."""
        routes = self.result["static_routes"]
        default = next(
            (r for r in routes if r.get("network") == "0.0.0.0"), None
        )
        self.assertIsNotNone(default)
        self.assertEqual(default["next_hop"], "10.0.0.1")

    def test_static_route_with_vrf(self):
        """Parser extracts VRF static route."""
        routes = self.result["static_routes"]
        vrf_route = next(
            (r for r in routes if r.get("vpn_instance") == "CLIENTE-A"), None
        )
        self.assertIsNotNone(vrf_route)
        self.assertEqual(vrf_route["network"], "10.10.10.0")
        self.assertEqual(vrf_route["netmask"], "255.255.255.0")
        self.assertEqual(vrf_route["next_hop"], "172.16.0.2")

    def test_static_route_no_description(self):
        """Parser sets description to None for Cisco routes
        (Cisco doesn't support description on ip route)."""
        routes = self.result["static_routes"]
        for route in routes:
            self.assertIsNone(route.get("description"))

    # ── BGP ────────────────────────────────────────────────────────────

    def test_bgp_blocks_found(self):
        """Parser identifies router bgp blocks."""
        self.assertGreater(len(self.result["bgp"]), 0)

    def test_bgp_as_number(self):
        """Parser extracts BGP AS number."""
        self.assertEqual(self.result["bgp"][0]["as_number"], "65000")
        self.assertEqual(self.result["bgp"][0]["local_as"], "65000")

    def test_bgp_router_id(self):
        """Parser extracts BGP router-id."""
        self.assertEqual(self.result["bgp"][0]["router_id"], "192.0.2.1")

    def test_bgp_peers_detected(self):
        """Parser extracts BGP peers."""
        peers = self.result["bgp"][0]["peers"]
        self.assertEqual(len(peers), 2)
        peer_ips = [p["ip"] for p in peers]
        self.assertIn("10.255.123.2", peer_ips)
        self.assertIn("10.255.124.2", peer_ips)

    def test_bgp_peer_remote_as(self):
        """Parser extracts BGP peer remote-as."""
        peers = self.result["bgp"][0]["peers"]
        peer = next(p for p in peers if p["ip"] == "10.255.123.2")
        self.assertEqual(peer["remote_as"], "64520")

    def test_bgp_peer_description(self):
        """Parser extracts BGP peer description."""
        peers = self.result["bgp"][0]["peers"]
        peer = next(p for p in peers if p["ip"] == "10.255.123.2")
        self.assertEqual(peer["description"], "CLIENTE-X")

    def test_bgp_peer_update_source(self):
        """Parser extracts BGP peer update-source."""
        peers = self.result["bgp"][0]["peers"]
        peer = next(p for p in peers if p["ip"] == "10.255.123.2")
        self.assertEqual(peer["update_source"], "Loopback0")
        self.assertEqual(peer["connect_interface"], "Loopback0")

    def test_bgp_peer_password_flag(self):
        """Parser extracts BGP password as flag (never stores the key)."""
        peers = self.result["bgp"][0]["peers"]
        peer = next(p for p in peers if p["ip"] == "10.255.123.2")
        self.assertTrue(peer["has_password"])
        self.assertEqual(peer["password_type"], "cisco_type_7")

    def test_bgp_peer_route_maps(self):
        """Parser extracts BGP peer route-map in/out."""
        peers = self.result["bgp"][0]["peers"]
        peer = next(p for p in peers if p["ip"] == "10.255.123.2")
        self.assertEqual(peer["route_policy_import"], "CLIENTE-IN")
        self.assertEqual(peer["route_policy_export"], "CLIENTE-OUT")

    def test_bgp_networks_detected(self):
        """Parser extracts BGP network advertisements."""
        networks = self.result["bgp"][0]["networks"]
        self.assertEqual(len(networks), 2)
        self.assertIn("200.200.200.0 mask 255.255.255.252", networks)
        self.assertIn("200.200.201.0 mask 255.255.255.252", networks)

    def test_bgp_has_ipv4_family(self):
        """Parser detects address-family ipv4 presence."""
        self.assertTrue(self.result["bgp"][0]["has_ipv4_family"])

    # ── Edge cases ─────────────────────────────────────────────────────

    def test_empty_config(self):
        """Parser handles empty config gracefully."""
        empty_parser = CiscoIOSParser("")
        result = empty_parser.parse()
        self.assertEqual(result["vendor"], "cisco")
        self.assertEqual(result["hostname"], "")
        self.assertEqual(result["block_count"], 0)
        self.assertEqual(len(result["interfaces"]), 0)
        self.assertEqual(len(result["bgp"]), 0)
        self.assertEqual(len(result["static_routes"]), 0)

    def test_partial_config(self):
        """Parser handles config with only hostname + one interface."""
        text = """hostname TESTE
!
interface GigabitEthernet0/0
 description TEST-IFACE
 no shutdown
!
end"""
        parser = CiscoIOSParser(text)
        result = parser.parse()
        self.assertEqual(result["hostname"], "TESTE")
        self.assertEqual(len(result["interfaces"]), 1)
        self.assertEqual(result["interfaces"][0]["name"], "GigabitEthernet0/0")
        self.assertEqual(result["interfaces"][0]["description"], "TEST-IFACE")

    def test_interface_type_classification(self):
        """Parser classifies interface types correctly."""
        cases = [
            ("GigabitEthernet0/0", "physical"),
            ("GigabitEthernet0/0.1234", "subinterface"),
            ("Loopback0", "loopback"),
            ("Null0", "null"),
        ]
        for name, expected_type in cases:
            parsed_type = CiscoIOSParser._classify_interface(name)
            self.assertEqual(parsed_type, expected_type, f"Mismatch for {name}")
