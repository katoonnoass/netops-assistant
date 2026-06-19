"""
Cisco IOS / IOS-XE Configuration Parser

Parses the output of 'show running-config' from Cisco IOS/IOS-XE devices.
This parser is deterministic — no AI involved, only pattern matching and
structural analysis of the configuration text.

Supported constructs:
    - hostname
    - interfaces (physical, subinterfaces with encapsulation dot1Q)
    - static routes (ip route, ip route vrf)
    - BGP (router bgp, neighbor, address-family ipv4)
"""

from __future__ import annotations

import re

from apps.parsers.base import BaseParser


class CiscoIOSParser(BaseParser):
    """Parser for Cisco IOS / IOS-XE configurations.

    Splits the raw configuration text into logical blocks and extracts
    structured information about interfaces, static routes, and BGP.
    """

    vendor = "cisco"

    # Regex patterns
    RE_HOSTNAME = re.compile(r"^hostname\s+(.+)", re.MULTILINE)
    RE_INTERFACE = re.compile(r"^interface\s+(\S+)", re.MULTILINE)
    RE_ROUTER_BGP = re.compile(r"^router bgp\s+(\d+)", re.MULTILINE)
    RE_IP_ROUTE = re.compile(r"^ip\s+route(?:s)?\s+(.+?)$", re.MULTILINE)

    # Block-starter commands
    BLOCK_STARTERS = (
        "interface",
        "router bgp",
        "router ospf",
        "router rip",
        "router eigrp",
        "router isis",
        "access-list",
        "ip access-list",
        "route-map",
        "prefix-list",
        "ip prefix-list",
        "vlan",
        "class-map",
        "policy-map",
        "crypto",
        "snmp-server",
        "ntp",
        "line ",
        "controller",
        "redundancy",
        "dialer",
        "bba-group",
    )

    def parse(self) -> dict:
        """Parse the raw Cisco IOS configuration text.

        Returns:
            dict: Structured representation with:
                - vendor: "cisco"
                - platform: "ios"
                - hostname: device hostname or ""
                - blocks: list of all blocks with type and content
                - interfaces: list of parsed interface dicts
                - static_routes: list of static route dicts
                - bgp: list of parsed BGP block dicts
                - raw: original text
                - block_count: total number of blocks found
                - raw_summary: counts of raw elements
        """
        text = self.raw_config

        result: dict = {
            "vendor": "cisco",
            "platform": "ios",
            "sysname": "",
            "hostname": "",
            "blocks": [],
            "interfaces": [],
            "bgp": [],
            "static_routes": [],
            "raw": text,
            "block_count": 0,
            "raw_summary": {},
        }

        if not text or not text.strip():
            return result

        result["hostname"] = self._extract_hostname(text)
        result["sysname"] = result["hostname"]

        blocks = self._split_blocks(text)
        result["blocks"] = blocks
        result["block_count"] = len(blocks)

        for block in blocks:
            btype = block["type"]
            if btype == "interface":
                parsed = self._parse_interface_block(block)
                result["interfaces"].append(parsed)
            elif btype == "bgp":
                parsed = self._parse_bgp_block(block)
                result["bgp"].append(parsed)

        result["static_routes"] = self._extract_static_routes(text)

        return result

    # ── helpers ────────────────────────────────────────────────────────

    def _extract_hostname(self, text: str) -> str:
        """Extract the device hostname from config."""
        match = self.RE_HOSTNAME.search(text)
        return match.group(1).strip() if match else ""

    def _split_blocks(self, text: str) -> list[dict]:
        """Split configuration text into logical blocks.

        Cisco config lines end with '!'.  A block starts at column 0 with a
        known command keyword and continues with sub-commands until the next
        column-0 command or a '!' line.

        Returns:
            list of dicts with keys: type, header, raw, lines
        """
        lines = text.splitlines()
        blocks: list[dict] = []
        current_block = None

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            # '!' at column 0 is a comment / separator — close current block
            # Indented '!' inside a block (e.g. inside router bgp) is kept
            if stripped == "!" and line.startswith("!"):
                if current_block:
                    blocks.append(self._finalize_block(current_block))
                    current_block = None
                continue

            is_block_starter = self._is_block_starter(stripped)
            is_line_command = self._is_line_command(stripped)

            if is_block_starter:
                if current_block:
                    blocks.append(self._finalize_block(current_block))
                block_type = self._detect_block_type(stripped)
                current_block = {
                    "type": block_type,
                    "header": stripped,
                    "lines": [line],
                    "raw_lines": [line],
                }
            elif is_line_command:
                if current_block:
                    blocks.append(self._finalize_block(current_block))
                    current_block = None
                blocks.append(self._make_leaf_block("line_command", stripped, line))
            elif current_block is not None:
                current_block["lines"].append(line)
                current_block["raw_lines"].append(line)
                current_block["header"] = current_block["raw_lines"][0]
            else:
                # Standalone column-0 commands that are neither blocks nor
                # line commands — detect type or skip
                btype = self._detect_block_type(stripped)
                if btype not in ("other", "unknown"):
                    blocks.append(self._make_leaf_block(btype, stripped, line))

        if current_block:
            blocks.append(self._finalize_block(current_block))

        return blocks

    def _is_block_starter(self, stripped: str) -> bool:
        """Check if a stripped line starts a new multi-line block."""
        lower = stripped.lower()
        for starter in self.BLOCK_STARTERS:
            if lower.startswith(starter) and (
                len(lower) == len(starter) or lower[len(starter)] in (" ", "\t")
            ):
                return True
        return False

    def _is_line_command(self, stripped: str) -> bool:
        """Check if a line is a standalone command (not a block)."""
        lower = stripped.lower()
        if lower.startswith("ip route") or lower.startswith("ip routes"):
            return True
        if stripped.startswith("!"):
            return False
        return False

    def _detect_block_type(self, header: str) -> str:
        """Detect block type from its header line."""
        lower = header.lower()

        if lower.startswith("interface"):
            return "interface"
        if lower.startswith("router bgp"):
            return "bgp"
        if lower.startswith("router ospf"):
            return "ospf"
        if lower.startswith("router eigrp"):
            return "eigrp"
        if lower.startswith("router rip"):
            return "rip"
        if lower.startswith("router isis"):
            return "isis"
        if lower.startswith("access-list") or lower.startswith("ip access-list"):
            return "acl"
        if lower.startswith("route-map"):
            return "route_map"
        if lower.startswith("ip prefix-list") or lower.startswith("prefix-list"):
            return "prefix_list"
        if lower.startswith("vlan"):
            return "vlan"
        if lower.startswith("class-map"):
            return "class_map"
        if lower.startswith("policy-map"):
            return "policy_map"
        if lower.startswith("crypto "):
            return "crypto"
        if lower.startswith("snmp-server"):
            return "snmp"
        if lower.startswith("ntp"):
            return "ntp"
        if lower.startswith("line "):
            return "line"
        if lower.startswith("controller"):
            return "controller"
        if lower.startswith("redundancy"):
            return "redundancy"
        if lower.startswith("dialer"):
            return "dialer"
        if lower.startswith("bba-group"):
            return "bba_group"
        if lower.startswith("hostname"):
            return "hostname"
        if lower.startswith("ip route") or lower.startswith("ip routes"):
            return "static_route"
        return "other"

    def _finalize_block(self, block: dict) -> dict:
        """Build final dict for a block before appending."""
        return {
            "type": block["type"],
            "header": block["raw_lines"][0].strip(),
            "raw": "\n".join(block["raw_lines"]),
            "lines": block["raw_lines"],
        }

    def _make_leaf_block(self, block_type: str, header: str, raw_line: str) -> dict:
        """Create a single-line block."""
        return {
            "type": block_type,
            "header": header,
            "raw": raw_line,
            "lines": [raw_line],
        }

    # ── Interface parser ──────────────────────────────────────────────

    def _parse_interface_block(self, block: dict) -> dict:
        """Extract structured data from an interface block.

        Handles:
          - Physical interfaces: GigabitEthernet0/0, Loopback0
          - Subinterfaces: GigabitEthernet0/0.1234 (encapsulation dot1Q)

        Returns a dict compatible with the rest of the system.
        """
        header = block["header"]
        interface_name = header[len("interface "):].strip()

        parsed: dict = {
            "name": interface_name,
            "type": self._classify_interface(interface_name),
            "parent": self._get_parent_interface(interface_name),
            "subinterface_number": self._get_subinterface_number(interface_name),
            "description": "",
            "ip_address": None,
            "vlan_type": None,
            "vlan_id": None,
            "vlan_type_extra": None,
            "second_vlan_id": None,
            "pe_vid": None,
            "ce_vid": None,
            "vsi_name": None,
            "shutdown": False,
            "has_ip": False,
            "has_dot1q": False,
            "encapsulation": None,
            "raw": block["raw"],
            "raw_lines": block["lines"],
        }

        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "!":
                continue

            # description
            if stripped.startswith("description "):
                parsed["description"] = stripped[len("description "):].strip().strip('"')

            # encapsulation dot1Q <vlan>
            elif stripped.startswith("encapsulation dot1Q"):
                parsed["has_dot1q"] = True
                parsed["encapsulation"] = "dot1q"
                parsed["vlan_type"] = "dot1q"
                vlan_match = re.search(r"dot1Q\s+(\d+)", stripped)
                if vlan_match:
                    parsed["vlan_id"] = int(vlan_match.group(1))

            # ip address <ip> <mask> [secondary]
            elif stripped.startswith("ip address "):
                ip_part = stripped[len("ip address "):].strip()
                # Remove trailing 'secondary' or other keywords
                ip_part = ip_part.split()[0:2] if len(ip_part.split()) >= 2 else [ip_part]
                if len(ip_part) >= 2:
                    parsed["ip_address"] = f"{ip_part[0]} {ip_part[1]}"
                    parsed["has_ip"] = True
                elif len(ip_part) == 1:
                    parsed["ip_address"] = ip_part[0]
                    parsed["has_ip"] = True

            # no shutdown / shutdown
            elif stripped == "shutdown":
                parsed["shutdown"] = True
            elif stripped == "no shutdown":
                parsed["shutdown"] = False

        return parsed

    @staticmethod
    def _classify_interface(name: str) -> str:
        """Classify interface type."""
        lower = name.lower()
        if lower.startswith("loopback"):
            return "loopback"
        if lower.startswith("null"):
            return "null"
        if lower.startswith("port-channel") or lower.startswith("po"):
            return "port_channel"
        if "." in lower:
            return "subinterface"
        return "physical"

    @staticmethod
    def _get_parent_interface(name: str) -> str | None:
        """Extract parent interface name if this is a subinterface."""
        if "." in name:
            return name.split(".")[0]
        return None

    @staticmethod
    def _get_subinterface_number(name: str) -> int | None:
        """Extract subinterface number if this is a subinterface."""
        if "." in name:
            try:
                return int(name.split(".")[1])
            except (ValueError, IndexError):
                return None
        return None

    # ── Static route parser ───────────────────────────────────────────

    def _extract_static_routes(self, text: str) -> list[dict]:
        """Extract all ip route commands from configuration.

        Cisco format:
            ip route <dest> <mask> <next-hop> [<distance>]
            ip route vrf <name> <dest> <mask> <next-hop> [<distance>]

        Description not natively supported on Cisco — all routes get
        description=None.
        """
        routes: list[dict] = []
        for match in self.RE_IP_ROUTE.finditer(text):
            route_text = match.group(1).strip()
            route: dict = {
                "raw": f"ip route {route_text}",
                "vpn_instance": None,
            }

            tokens = route_text.split()
            pos = 0

            # Check for vrf
            if pos < len(tokens) and tokens[pos].lower() == "vrf":
                pos += 1
                if pos < len(tokens):
                    route["vpn_instance"] = tokens[pos]
                    pos += 1

            # Positional: dest, mask, next-hop
            if len(tokens) > pos:
                route["network"] = tokens[pos]
                pos += 1
            if len(tokens) > pos:
                route["netmask"] = tokens[pos]
                pos += 1
            if len(tokens) > pos:
                route["next_hop"] = tokens[pos]
                pos += 1

            # Optional numeric distance at the end
            if pos < len(tokens) and tokens[pos].isdigit():
                route["preference"] = tokens[pos]
                pos += 1

            routes.append(route)

        return routes

    # ── BGP parser ────────────────────────────────────────────────────

    def _parse_bgp_block(self, block: dict) -> dict:
        """Extract structured data from a router bgp block.

        Cisco format:
            router bgp <AS>
             bgp router-id <id>
             neighbor <ip> remote-as <AS>
             neighbor <ip> description <text>
             neighbor <ip> update-source <interface>
             neighbor <ip> password <type> <key>
             !
             address-family ipv4
              neighbor <ip> activate
              neighbor <ip> route-map <NAME> in
              neighbor <ip> route-map <NAME> out
              network <prefix> mask <mask>
             exit-address-family
        """
        header = block["header"]
        local_as = header[len("router bgp "):].strip()

        parsed: dict = {
            "as_number": local_as,
            "local_as": local_as,
            "router_id": None,
            "peers": [],
            "networks": [],
            "has_ipv4_family": False,
            "raw": block["raw"],
        }

        # Track peers by IP for cross-referencing between global and AF
        peers_by_ip: dict[str, dict] = {}
        in_ipv4_family = False

        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "!":
                continue

            # bgp router-id
            if stripped.startswith("bgp router-id "):
                parsed["router_id"] = stripped[len("bgp router-id "):].strip()
                continue

            # Track ipv4-family
            if stripped.startswith("address-family ipv4"):
                in_ipv4_family = True
                parsed["has_ipv4_family"] = True
                continue
            if stripped.startswith("exit-address-family"):
                in_ipv4_family = False
                continue

            # neighbor <ip> remote-as <AS>
            neighbor_remote = re.match(
                r"^neighbor\s+(\S+)\s+remote-as\s+(\d+)", stripped
            )
            if neighbor_remote:
                peer_ip = neighbor_remote.group(1)
                if peer_ip not in peers_by_ip:
                    peer = {
                        "ip": peer_ip,
                        "remote_as": neighbor_remote.group(2),
                        "description": "",
                        "route_policy_import": None,
                        "route_policy_export": None,
                        "connect_interface": None,
                        "update_source": None,
                        "has_password": False,
                        "password_type": None,
                        "enabled": True,
                    }
                    peers_by_ip[peer_ip] = peer
                    parsed["peers"].append(peer)
                continue

            # Lines starting with "neighbor "
            if stripped.startswith("neighbor "):
                self._parse_neighbor_line(stripped, peers_by_ip, in_ipv4_family)
                continue

            # network <prefix> mask <mask>
            if stripped.startswith("network "):
                network_str = stripped[len("network "):].strip()
                parsed["networks"].append(network_str)
                continue

        return parsed

    def _parse_neighbor_line(
        self, stripped: str, peers_by_ip: dict, in_ipv4_family: bool
    ) -> None:
        """Parse a neighbor sub-command and update the peer dict."""
        ip_match = re.match(r"^neighbor\s+(\S+)", stripped)
        if not ip_match:
            return
        peer_ip = ip_match.group(1)
        peer = peers_by_ip.get(peer_ip)
        if not peer:
            return

        rest = stripped[len(f"neighbor {peer_ip}"):].strip()

        # description
        desc_match = re.match(r"^description\s+(.+)", rest)
        if desc_match:
            peer["description"] = desc_match.group(1).strip().strip('"')
            return

        # update-source
        us_match = re.match(r"^update-source\s+(\S+)", rest)
        if us_match:
            peer["update_source"] = us_match.group(1)
            peer["connect_interface"] = us_match.group(1)
            return

        # route-map <NAME> in/out
        rp_match = re.match(r"^route-map\s+(\S+)\s+(in|out)", rest)
        if rp_match:
            policy_name = rp_match.group(1)
            direction = rp_match.group(2)
            if direction == "in":
                peer["route_policy_import"] = policy_name
            else:
                peer["route_policy_export"] = policy_name
            return

        # password — mark as flag, never store the actual key
        if re.match(r"^password\s+", rest):
            peer["has_password"] = True
            # Try to detect type
            pw_rest = rest[len("password "):].strip()
            if pw_rest.startswith("7 "):
                peer["password_type"] = "cisco_type_7"
            elif pw_rest.startswith("0 "):
                peer["password_type"] = "plain"
            else:
                peer["password_type"] = "unknown"
            return

        # activate (inside address-family)
        if rest == "activate":
            peer["enabled"] = True
            return
