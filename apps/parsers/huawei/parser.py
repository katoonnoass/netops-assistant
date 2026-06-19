"""
Huawei VRP Configuration Parser

Parses the output of 'display current-configuration' from Huawei/VRP devices.
This parser is deterministic — no AI involved, only pattern matching and
structural analysis of the configuration text.
"""

import re

from apps.parsers.base import BaseParser


class HuaweiVRPParser(BaseParser):
    """Parser for Huawei VRP (Versatile Routing Platform) configurations.

    Splits the raw configuration text into logical blocks and extracts
    structured information about interfaces, routing, BGP, and other sections.
    """

    vendor = "huawei"

    # Regex patterns for block detection
    RE_INTERFACE = re.compile(r"^interface\s+(\S+)", re.MULTILINE)
    RE_BGP = re.compile(r"^bgp\s+(\d+)", re.MULTILINE)
    RE_ROUTE_STATIC = re.compile(r"^ip\s+route-static\s+(.+?)$", re.MULTILINE)
    RE_SYSNAME = re.compile(r"^sysname\s+(.+)", re.MULTILINE)
    RE_HEADER_COMMANDS = re.compile(
        r"^(sysname|undo\s+terminal|device-id|info-center|clock|user-interface"
        r"|authentication|super|service-manager|set\s+overall|undo\s+info|"
        r"dns|router\s+id)",  # noqa: E501
        re.MULTILINE,
    )

    # Block-starter commands (commands that introduce a multi-line block)
    BLOCK_STARTERS = (
        "interface",
        "bgp",
        "acl",
        "route-policy",
        "ip prefix-list",
        "ip ip-prefix",
        "ip as-path-filter",
        "ip community-filter",
        "ospf",
        "isis",
        "mpls",
        "vlan",
        "stp",
        "dhcp",
        "snmp-agent",
        "ntp-service",
        "bridge",
        "l2vpn",
        "vsi",
        "vs",
        "ike",
        "ipsec",
        "pki",
        "ipip",
        "vxlan",
        "evpn",
        "cfm",
        "mstp",
        "rrpp",
        "sep",
        "smart-link",
        # BNG/AAA blocks
        "aaa",
        "radius-server",
        "radius server",
        "ip pool",
        "domain",
        "bas",
        "authentication-scheme",
        "authorization-scheme",
        "accounting-scheme",
        # Management blocks
        "user-interface",
        "info-center",
        "stelnet",
        "ssh",
    )

    # BNG indicator keywords
    BNG_INDICATOR_KEYWORDS = [
        "bas",
        "access-type layer2-subscriber",
        "access-type layer3-subscriber",
        "pppoe",
        "ipoe",
        "authentication-scheme",
        "accounting-scheme",
        "radius-server",
        "domain",
        "ip pool",
        "dns-server",
        "gateway",
        "lease",
        "access-limit",
        "user-group",
        "qos-profile",
        "subscriber",
    ]

    def parse(self) -> dict:
        """Parse the raw VRP configuration text.

        Returns:
            dict: Structured representation with the following keys:
                - vendor: "huawei"
                - sysname: device hostname or empty string
                - blocks: list of all blocks with type and content
                - interfaces: list of parsed interface blocks
                - bgp: list of parsed BGP blocks
                - static_routes: list of static route dictionaries
                - raw: original text
                - block_count: total number of blocks found
        """
        text = self.raw_config

        result: dict = {
            "vendor": "huawei",
            "sysname": "",
            "blocks": [],
            "interfaces": [],
            "bgp": [],
            "vsi": [],
            "static_routes": [],
            "aaa": [],
            "radius_servers": [],
            "aaa_domains": [],
            "ip_pools": [],
            "bas_interfaces": [],
            "auth_schemes": [],
            "acct_schemes": [],
            "bng_indicators": [],
            # Management & observability
            "snmp": {
                "enabled": False,
                "versions": [],
                "communities": [],
                "trap_hosts": [],
                "users": [],
                "groups": [],
                "acl_refs": [],
                "raw_lines": [],
            },
            "ntp": {
                "enabled": False,
                "servers": [],
                "source_interface": None,
                "authentication_enabled": False,
                "raw_lines": [],
            },
            "syslog": {
                "enabled": False,
                "log_hosts": [],
                "facilities": [],
                "raw_lines": [],
            },
            "local_users": [],
            "vty_lines": [],
            "prefix_lists": [],
            "route_policies": [],
            "acls": [],
            "as_path_filters": [],
            "community_filters": [],
            "ssh": {
                "enabled": False,
                "users": [],
                "raw_lines": [],
            },
            "management_access": {
                "has_local_users": False,
                "has_vty": False,
                "has_ssh": False,
                "has_telnet": False,
                "has_acl_on_vty": False,
            },
            "acls": [],
            # L2 switching
            "vlans": [],
            "stp": {
                "enabled": False,
                "mode": None,
                "regions": [],
                "instances": [],
                "raw_lines": [],
            },
            "ospf": [],
            "raw": text,
            "block_count": 0,
        }

        if not text or not text.strip():
            return result

        result["sysname"] = self._extract_sysname(text)
        blocks = self._split_blocks(text)
        result["blocks"] = blocks
        result["block_count"] = len(blocks)

        for block in blocks:
            if block["type"] == "interface":
                parsed = self._parse_interface_block(block)
                result["interfaces"].append(parsed)
            elif block["type"] == "bgp":
                parsed = self._parse_bgp_block(block)
                result["bgp"].append(parsed)
            elif block["type"] == "vsi":
                parsed = self._parse_vsi_block(block)
                result["vsi"].append(parsed)
            elif block["type"] == "aaa":
                parsed = self._parse_aaa_block(block)
                result["aaa"].append(parsed)
            elif block["type"] == "radius_server":
                parsed = self._parse_radius_block(block)
                result["radius_servers"].append(parsed)
            elif block["type"] == "ip_pool":
                parsed = self._parse_ip_pool_block(block)
                result["ip_pools"].append(parsed)
            elif block["type"] == "aaa_domain":
                parsed = self._parse_aaa_domain_block(block)
                result["aaa_domains"].append(parsed)
            elif block["type"] == "bas":
                parsed = self._parse_bas_block(block)
                result["bas_interfaces"].append(parsed)
            elif block["type"] == "auth_scheme":
                parsed = self._parse_generic_block(block, "auth_scheme")
                result["auth_schemes"].append(parsed)
            elif block["type"] == "acct_scheme":
                parsed = self._parse_generic_block(block, "acct_scheme")
                result["acct_schemes"].append(parsed)
            elif block["type"] == "snmp":
                self._parse_snmp_line(block["header"], result["snmp"])
            elif block["type"] == "ntp":
                self._parse_ntp_line(block["header"], result["ntp"])
            elif block["type"] == "syslog":
                self._parse_syslog_line(block["header"], result["syslog"])
            elif block["type"] == "vty":
                parsed = self._parse_vty_block(block)
                result["vty_lines"].append(parsed)
            elif block["type"] == "ssh":
                self._parse_ssh_line(block["header"], result["ssh"])
            elif block["type"] == "local_user":
                self._parse_local_user_line(block["header"], result)
            elif block["type"] == "acl":
                parsed = self._parse_acl_block(block)
                if parsed:
                    result["acls"].append(parsed)
            elif block["type"] == "route-policy":
                parsed = self._parse_route_policy_block(block)
                if parsed:
                    result["route_policies"].append(parsed)
            elif block["type"] == "as-path-filter":
                parsed = self._parse_as_path_filter_block(block)
                if parsed:
                    result["as_path_filters"].append(parsed)
            elif block["type"] == "community-filter":
                parsed = self._parse_community_filter_block(block)
                if parsed:
                    result["community_filters"].append(parsed)
            elif block["type"] == "prefix-list":
                parsed = self._parse_prefix_list_block(block)
                if parsed:
                    result["prefix_lists"].append(parsed)
            elif block["type"] == "vlan":
                header = block["header"]
                if header.lower().startswith("vlan batch"):
                    self._parse_vlan_batch_line(header, result)
                else:
                    parsed = self._parse_vlan_block(block)
                    if parsed:
                        result["vlans"].append(parsed)
            elif block["type"] == "stp":
                self._parse_stp_block(block, result)
            elif block["type"] == "ospf":
                parsed = self._parse_ospf_block(block)
                if parsed:
                    result["ospf"].append(parsed)

        result["static_routes"] = self._extract_static_routes(text)
        result["bng_indicators"] = self._extract_bng_indicators(result)

        # Post-process: extract local-users from raw text
        self._extract_all_local_users(result)

        # Post-process: extract AAA sub-blocks (auth schemes, domains, etc.)
        self._extract_aaa_sub_blocks(result)

        # Build management_access summary
        result["management_access"] = self._build_management_access(result)

        # Post-process: tie ACL references to definitions in SNMP data
        self._enrich_acl_references(result)

        # Deduplicate VLANs: individual blocks override batch entries
        self._deduplicate_vlans(result)

        # Post-process: associate Eth-Trunk members
        self._associate_eth_trunk_members(result)

        # Post-process: merge as-path/community filters with same name
        self._merge_filters_by_name(result, "as_path_filters")
        self._merge_filters_by_name(result, "community_filters")

        return result

    def _extract_sysname(self, text: str) -> str:
        """Extract the device sysname (hostname) from config."""
        match = self.RE_SYSNAME.search(text)
        return match.group(1).strip() if match else ""

    def _split_blocks(self, text: str) -> list:
        """Split configuration text into logical blocks.

        A block starts at column 0 with a known command keyword and continues
        with indented sub-commands until the next column-0 command.

        Returns:
            list of dicts with keys:
                - type: block type (interface, bgp, route-policy, etc.)
                - header: first line of the block
                - lines: list of lines in the block
                - raw: original text of the block
        """
        lines = text.splitlines()
        blocks = []
        current_block = None

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            # Check if this line starts a new block (column 0 + known starter)
            # Lines starting with whitespace are continuations, never block starters
            is_indented = line[:1] in (" ", "\t")
            is_block_starter = False if is_indented else self._is_block_starter(stripped)

            # Check for line-level commands (not part of a block)
            is_line_command = self._is_line_command(stripped)

            if is_block_starter:
                # Save previous block
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
                # Line-level commands (not part of any block)
                if current_block:
                    blocks.append(self._finalize_block(current_block))
                    current_block = None
                blocks.append(self._make_leaf_block("line_command", stripped, line))
            elif current_block is not None:
                # Continuation of current block
                current_block["lines"].append(line)
                current_block["raw_lines"].append(line)
                # Update raw text
                current_block["header"] = current_block["raw_lines"][0]
            else:
                # Lines at column 0 that are not block starters or line cmds
                # They could be standalone (like sysname, vlan batch, etc.)
                block_type = self._detect_block_type(stripped)
                if block_type != "other":
                    blocks.append(
                        self._make_leaf_block(block_type, stripped, line)
                    )
                # If it's truly unknown, we skip

        if current_block:
            blocks.append(self._finalize_block(current_block))

        return blocks

    def _is_block_starter(self, stripped: str) -> bool:
        """Check if a stripped line starts a new block."""
        for starter in self.BLOCK_STARTERS:
            if stripped.startswith(starter) and (
                len(stripped) == len(starter)
                or stripped[len(starter)] in (" ", "\t")
            ):
                # Special case: 'acl' followed by a number and direction
                # (e.g. "acl 2001 inbound") is NOT a block starter
                if starter == "acl":
                    rest = stripped[len(starter):].strip()
                    if rest and not rest.startswith("number") and not rest.startswith("name"):
                        # Check if it's an inline ACL reference like "acl 2001 inbound"
                        # These don't start ACL blocks
                        continue
                return True
        # Special case: interface range (XGigabitEthernet, Eth-Trunk, etc.)
        if re.match(r"^(interface)\s+", stripped, re.IGNORECASE):
            return True
        return False

    def _is_line_command(self, stripped: str) -> bool:
        """Check if a line is a standalone command (not a block)."""
        # 'ip route-static' lines are standalone
        if stripped.startswith("ip route-static"):
            return True
        # Lines starting with '#' are not commands, they're separators
        if stripped.startswith("#"):
            return False
        # Lines starting with typical standalone commands
        if re.match(
            r"^(ip\s+route-static|undo\s+info-center|vlan\s+batch|return)$",
            stripped,
        ):
            return True
        return False

    def _detect_block_type(self, header: str) -> str:
        """Detect the block type from its header line."""
        header_lower = header.lower()

        if header_lower.startswith("interface"):
            return "interface"
        if header_lower.startswith("bgp"):
            return "bgp"
        if header_lower.startswith("acl"):
            return "acl"
        if header_lower.startswith("route-policy"):
            return "route-policy"
        if header_lower.startswith("ip prefix-list"):
            return "prefix-list"
        if header_lower.startswith("ip ip-prefix"):
            return "prefix-list"
        if header_lower.startswith("ip as-path-filter"):
            return "as-path-filter"
        if header_lower.startswith("ip community-filter"):
            return "community-filter"
        if header_lower.startswith("ospf"):
            return "ospf"
        if header_lower.startswith("isis"):
            return "isis"
        if header_lower.startswith("mpls"):
            return "mpls"
        if header_lower.startswith("vlan "):
            return "vlan"
        if header_lower.startswith("stp"):
            return "stp"
        if header_lower.startswith("dhcp"):
            return "dhcp"
        if header_lower.startswith("snmp"):
            return "snmp"
        if header_lower.startswith("ntp"):
            return "ntp"
        if header_lower.startswith("l2vpn") or header_lower.startswith("bridge"):
            return "l2vpn"
        if header_lower.startswith("vsi "):
            return "vsi"
        if header_lower in ("aaa",):
            return "aaa"
        if header_lower.startswith("radius-server") or header_lower.startswith("radius server"):
            return "radius_server"
        if header_lower.startswith("ip pool"):
            return "ip_pool"
        if header_lower.startswith("domain "):
            return "aaa_domain"
        if header_lower in ("bas",):
            return "bas"
        if header_lower.startswith("authentication-scheme"):
            return "auth_scheme"
        if header_lower.startswith("accounting-scheme"):
            return "acct_scheme"
        if header_lower.startswith("ike") or header_lower.startswith("ipsec"):
            return "ipsec"
        if header_lower.startswith("pki"):
            return "pki"
        if header_lower.startswith("sysname"):
            return "sysname"
        if header_lower.startswith("ip route-static"):
            return "static_route"
        if header_lower.startswith("vlan batch"):
            return "vlan_batch"
        if header_lower.startswith("router id"):
            return "router_id"
        if header_lower.startswith("info-center"):
            return "syslog"
        if header_lower.startswith("stelnet"):
            return "ssh"
        if header_lower.startswith("ssh"):
            return "ssh"
        if header_lower.startswith("user-interface"):
            return "vty"
        if header_lower.startswith("local-user"):
            return "local_user"
        return "other"

    def _finalize_block(self, block: dict) -> dict:
        """Build the final dict for a block before appending."""
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

    def _parse_interface_block(self, block: dict) -> dict:
        """Extract structured data from an interface block.

        Handles:
        - Physical interfaces: GigabitEthernet X/Y/Z
        - Eth-Trunks: Eth-Trunk N
        - Subinterfaces: GigabitEthernet X/Y/Z.N (dot1q)
        """
        header = block["header"]  # e.g. "interface GigabitEthernet0/0/1"
        interface_name = header[len("interface "):].strip()

        parsed = {
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
            "raw": block["raw"],
        }

        for line in block["lines"][1:]:  # Skip the header
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue

            if stripped.startswith("description "):
                parsed["description"] = stripped[len("description "):].strip().strip('"')

            elif stripped.startswith("ip address "):
                ip_part = stripped[len("ip address "):].strip()
                parsed["ip_address"] = ip_part

            elif stripped == "shutdown":
                parsed["shutdown"] = True

            elif stripped.startswith("dot1q termination vid"):
                parsed["vlan_type"] = "dot1q"
                vid_match = re.search(r"vid\s+(\d+)", stripped)
                if vid_match:
                    parsed["vlan_id"] = vid_match.group(1)

            elif stripped.startswith("vlan-type dot1q"):
                parsed["vlan_type"] = "dot1q"
                # Check for QinQ: "vlan-type dot1q <vlan> second-dot1q <inner_vlan>"
                qinq_match = re.match(
                    r"vlan-type dot1q\s+(\d+)\s+second-dot1q\s+(\d+)", stripped
                )
                if qinq_match:
                    parsed["vlan_id"] = qinq_match.group(1)
                    parsed["second_vlan_id"] = qinq_match.group(2)
                    parsed["vlan_type_extra"] = "qinq"
                else:
                    vid_match = re.search(r"(\d+)", stripped[len("vlan-type dot1q"):])
                    if vid_match:
                        parsed["vlan_id"] = vid_match.group(1)

            elif stripped.startswith("qinq termination"):
                parsed["vlan_type"] = "qinq_termination"
                parsed["vlan_type_extra"] = "qinq"
                qinq_match = re.match(
                    r"qinq termination pe-vid\s+(\d+)\s+ce-vid\s+(\d+)", stripped
                )
                if qinq_match:
                    parsed["pe_vid"] = qinq_match.group(1)
                    parsed["ce_vid"] = qinq_match.group(2)

            elif stripped.startswith("l2 binding vsi"):
                l2_match = re.match(r"l2 binding vsi\s+(\S+)", stripped)
                if l2_match:
                    parsed["vsi_name"] = l2_match.group(1)
                    parsed["vlan_type"] = "l2binding"

            # ── L2 port mode ───────────────────────────────────────
            elif stripped.startswith("port link-type "):
                parsed["port_mode"] = stripped[len("port link-type "):].strip()
            elif stripped.startswith("port default vlan "):
                parsed["access_vlan"] = stripped[len("port default vlan "):].strip()
            elif stripped.startswith("port trunk allow-pass vlan "):
                val = stripped[len("port trunk allow-pass vlan "):].strip()
                parsed["trunk_allowed_vlans"] = val
            elif stripped.startswith("port trunk pvid vlan "):
                parsed["trunk_pvid"] = stripped[len("port trunk pvid vlan "):].strip()
            elif stripped.startswith("port hybrid untagged vlan "):
                parsed["hybrid_untagged_vlans"] = stripped[len("port hybrid untagged vlan "):].strip()
            elif stripped.startswith("port hybrid tagged vlan "):
                parsed["hybrid_tagged_vlans"] = stripped[len("port hybrid tagged vlan "):].strip()
            elif stripped.startswith("port hybrid pvid vlan "):
                parsed["hybrid_pvid"] = stripped[len("port hybrid pvid vlan "):].strip()

            # ── Eth-Trunk member ──────────────────────────────────
            elif stripped.startswith("eth-trunk "):
                trunk_id = stripped[len("eth-trunk "):].strip()
                parsed["eth_trunk_id"] = trunk_id
                parsed["eth_trunk_name"] = f"Eth-Trunk{trunk_id}"
                parsed["is_eth_trunk_member"] = True

            # ── STP per-interface ──────────────────────────────────
            elif stripped == "stp enable":
                parsed["stp_enabled"] = True
            elif stripped == "stp disable":
                parsed["stp_enabled"] = False
                parsed["stp_disabled"] = True
            elif stripped == "stp edged-port enable":
                parsed["stp_edge_port"] = True

            # ── Misc ───────────────────────────────────────────────
            elif stripped.startswith("broadcast-suppression "):
                parsed["storm_control_broadcast"] = stripped[len("broadcast-suppression "):].strip()
            elif stripped == "loopback-detect enable":
                parsed["loopback_detection"] = True
            elif stripped == "lldp enable":
                parsed["lldp_enabled"] = True

            # ── L2 interface flag ──────────────────────────────────
            if parsed.get("port_mode") in ("access", "trunk", "hybrid"):
                parsed["is_l2_port"] = True
            else:
                parsed.setdefault("is_l2_port", False)

        return parsed

    # ── VLAN parser ─────────────────────────────────────────────────

    @staticmethod
    def _expand_huawei_vlan_list(vlan_str: str) -> list[int]:
        """Expand a Huawei VLAN string to a list of ints.

        Handles formats:
        - '10 20 100 to 110'  (space + 'to')
        - '1-50'              (hyphen)
        - '10,20,30'          (comma)
        """
        result: list[int] = []
        if not vlan_str or vlan_str.strip().lower() == "all":
            return result
        # Replace commas with spaces
        vlan_str = vlan_str.replace(",", " ")
        tokens = vlan_str.split()
        i = 0
        while i < len(tokens):
            # Check for hyphen range (e.g. "1-50")
            if "-" in tokens[i]:
                parts = tokens[i].split("-")
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    start, end = int(parts[0]), int(parts[1])
                    if start < end and end <= 4094:
                        result.extend(range(start, end + 1))
                    i += 1
                    continue
            if tokens[i].isdigit():
                val = int(tokens[i])
                if i + 2 < len(tokens) and tokens[i + 1].lower() == "to" and tokens[i + 2].isdigit():
                    end = int(tokens[i + 2])
                    if val < end and end <= 4094:
                        result.extend(range(val, end + 1))
                    i += 3
                else:
                    if val <= 4094:
                        result.append(val)
                    i += 1
            else:
                i += 1
        return sorted(set(result))

    def _parse_vlan_block(self, block: dict) -> dict | None:
        """Parse a 'vlan <id>' block."""
        header = block["header"]
        m = re.match(r"vlan\s+(\d+)", header)
        if not m:
            return None
        vlan_id = m.group(1)
        entry: dict = {
            "vlan_id": int(vlan_id),
            "name": "",
            "description": "",
            "source": "vlan",
            "raw_lines": [block["raw"]],
        }
        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue
            if stripped.startswith("description "):
                desc = stripped[len("description "):].strip().strip('"')
                entry["description"] = desc
                if not entry["name"]:
                    entry["name"] = desc
            elif stripped.startswith("name "):
                entry["name"] = stripped[len("name "):].strip().strip('"')
        return entry

    def _parse_vlan_batch_line(self, header: str, result: dict) -> None:
        """Parse a 'vlan batch ...' line and add VLAN entries."""
        val = header[len("vlan batch"):].strip()
        expanded = self._expand_huawei_vlan_list(val)
        for vid in expanded:
            # Don't duplicate if already defined as individual VLAN
            existing = [v for v in result["vlans"] if v["vlan_id"] == vid]
            if not existing:
                result["vlans"].append({
                    "vlan_id": vid,
                    "name": "",
                    "description": "",
                    "source": "vlan batch",
                    "raw_lines": [header],
                })

    # ── STP parser ──────────────────────────────────────────────────

    def _parse_stp_block(self, block: dict, result: dict) -> None:
        """Parse an STP or MSTP block."""
        header = block["header"]
        lower = header.lower()

        result["stp"]["enabled"] = True
        result["stp"]["raw_lines"].append(block["raw"])

        # Detect global STP enable/disable
        if lower.startswith("stp") and "region" not in lower:
            if " disable" in lower:
                result["stp"]["enabled"] = False
            elif " enable" in lower:
                result["stp"]["enabled"] = True
            # stp mode
            mode_m = re.search(r"stp\s+mode\s+(\S+)", lower)
            if mode_m:
                result["stp"]["mode"] = mode_m.group(1)

        # stp region-configuration
        if "region-configuration" in lower:
            region: dict = {"name": "", "revision": None, "instances": []}
            for line in block["lines"][1:]:
                stripped = line.strip()
                if not stripped or stripped == "#":
                    continue
                sl = stripped.lower()
                if sl.startswith("region-name "):
                    region["name"] = stripped[len("region-name "):].strip()
                elif sl.startswith("revision-level "):
                    rev = sl[len("revision-level "):].strip()
                    if rev.isdigit():
                        region["revision"] = int(rev)
                elif sl.startswith("instance "):
                    inst_m = re.match(r"instance\s+(\d+)\s+vlan\s+(.+)", stripped, re.IGNORECASE)
                    if inst_m:
                        inst_id = int(inst_m.group(1))
                        vlans = self._expand_huawei_vlan_list(inst_m.group(2).strip())
                        region["instances"].append({
                            "instance_id": inst_id,
                            "vlans": vlans,
                        })
                        result["stp"]["instances"].append({
                            "instance_id": inst_id,
                            "vlans": vlans,
                        })
            result["stp"]["regions"].append(region)

    def _parse_ospf_block(self, block: dict) -> dict | None:
        """Parse an OSPF configuration block.

        Huawei VRP format:
            ospf <process_id> [router-id <x.x.x.x>]
             area <x.x.x.x>
              network <x.x.x.x> <wildcard>
              [passive-interface <iface>]
             [import-route <protocol>]
             [default-route-advertise]
             [bandwidth-reference <value>]

        Returns:
            dict with keys: process_id, router_id, areas, networks,
            passive_interfaces, redistribute, default_route_advertise,
            reference_bandwidth.
        """
        header = block["header"]
        lines = block.get("lines", [])

        m = re.match(r"ospf\s+(\d+)", header, re.IGNORECASE)
        if not m:
            return None
        process_id = m.group(1)

        parsed = {
            "process_id": process_id,
            "router_id": None,
            "areas": [],
            "networks": [],
            "passive_interfaces": [],
            "redistribute": [],
            "default_route_advertise": False,
            "reference_bandwidth": None,
            "raw": block.get("raw", ""),
        }

        # Extract router-id from header if present
        rid_m = re.search(r"router-id\s+(\S+)", header, re.IGNORECASE)
        if rid_m:
            parsed["router_id"] = rid_m.group(1)

        current_area = None
        for line in lines[1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue

            sl = stripped.lower()

            # router-id inside block
            if sl.startswith("router-id"):
                rid = re.search(r"router-id\s+(\S+)", stripped, re.IGNORECASE)
                if rid:
                    parsed["router_id"] = rid.group(1)
                continue

            # area definition
            area_m = re.match(r"area\s+(\S+)", stripped, re.IGNORECASE)
            if area_m:
                current_area = area_m.group(1)
                if current_area not in parsed["areas"]:
                    parsed["areas"].append(current_area)
                continue

            # network inside area
            net_m = re.match(
                r"network\s+(\S+)\s+(\S+)", stripped, re.IGNORECASE
            )
            if net_m:
                entry = {
                    "network": net_m.group(1),
                    "wildcard": net_m.group(2),
                    "area": current_area,
                }
                parsed["networks"].append(entry)
                continue

            # passive-interface
            pi_m = re.match(
                r"passive-interface\s+(\S+)", stripped, re.IGNORECASE
            )
            if pi_m:
                parsed["passive_interfaces"].append(pi_m.group(1))
                continue

            # import-route (redistribution)
            ir_m = re.match(
                r"import-route\s+(\S+)", stripped, re.IGNORECASE
            )
            if ir_m:
                redistribute_entry = {"protocol": ir_m.group(1)}
                rest = stripped[len(f"import-route {ir_m.group(1)}"):].strip()
                if rest:
                    redistribute_entry["details"] = rest
                parsed["redistribute"].append(redistribute_entry)
                continue

            # default-route-advertise
            if "default-route-advertise" in sl:
                parsed["default_route_advertise"] = True
                continue

            # bandwidth-reference
            br_m = re.search(
                r"bandwidth-reference\s+(\d+)", stripped, re.IGNORECASE
            )
            if br_m:
                parsed["reference_bandwidth"] = int(br_m.group(1))
                continue

        return parsed

    def _deduplicate_vlans(self, result: dict) -> None:
        """Remove batch VLANs that have individual block overrides."""
        seen: dict[int, int] = {}  # vlan_id -> index in list
        unique: list = []
        for vlan in result.get("vlans", []):
            vid = vlan["vlan_id"]
            if vid in seen:
                idx = seen[vid]
                # Individual block overrides batch
                if vlan["source"] == "vlan":
                    unique[idx] = vlan
            else:
                seen[vid] = len(unique)
                unique.append(vlan)
        result["vlans"] = unique

    def _associate_eth_trunk_members(self, result: dict) -> None:
        """Associate physical member interfaces with Eth-Trunk interfaces."""
        members_by_trunk: dict[str, list[str]] = {}
        for iface in result.get("interfaces", []):
            trunk_id = iface.get("eth_trunk_id")
            if trunk_id:
                key = f"Eth-Trunk{trunk_id}"
                members_by_trunk.setdefault(key, []).append(iface["name"])
        if not members_by_trunk:
            return
        for iface in result.get("interfaces", []):
            if iface.get("type") in ("eth-trunk", "port_channel") and iface["name"] in members_by_trunk:
                iface["members"] = members_by_trunk[iface["name"]]

    def _merge_filters_by_name(self, result: dict, key: str) -> None:
        """Merge filter entries with same name (as-path-filter, community-filter).
        Also deduplicates rules by their 'raw' field.
        """
        entries = result.get(key, [])
        if not entries:
            return
        merged: dict[str, dict] = {}
        for entry in entries:
            name = entry.get("name", "")
            if name in merged:
                seen_raws = {r["raw"] for r in merged[name].get("rules", [])}
                for rule in entry.get("rules", []):
                    if rule.get("raw", "") not in seen_raws:
                        merged[name]["rules"].append(rule)
                        seen_raws.add(rule.get("raw", ""))
            else:
                merged[name] = dict(entry)
                merged[name]["rules"] = list(entry.get("rules", []))
        result[key] = list(merged.values())

    def _parse_bgp_block(self, block: dict) -> dict:
        """Extract structured data from a BGP block."""
        header = block["header"]
        as_number = header[len("bgp "):].strip()

        parsed = {
            "as_number": as_number,
            "peers": [],
            "networks": [],
            "has_ipv4_family": False,
            "raw": block["raw"],
        }

        # Track current peer and whether we're inside ipv4-family
        peers_by_ip: dict[str, dict] = {}
        in_ipv4_family = False

        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue

            # Track ipv4-family unicast section
            if stripped.startswith("ipv4-family"):
                in_ipv4_family = True
                parsed["has_ipv4_family"] = True
                continue

            # Peer definition
            peer_match = re.match(
                r"^peer\s+(\S+)\s+as-number\s+(\d+)", stripped
            )
            if peer_match:
                peer_ip = peer_match.group(1)
                if peer_ip not in peers_by_ip:
                    peer = {
                        "ip": peer_ip,
                        "remote_as": peer_match.group(2),
                        "description": "",
                        "route_policy_import": None,
                        "route_policy_export": None,
                        "connect_interface": None,
                        "has_password": False,
                        "password_type": None,
                        "enabled": True,
                    }
                    peers_by_ip[peer_ip] = peer
                    parsed["peers"].append(peer)
                continue

            # Network advertisement
            net = self._parse_bgp_network(stripped)
            if net:
                parsed["networks"].append(net)
                continue

            # Lines starting with "peer " — handle various attributes
            if stripped.startswith("peer "):
                self._parse_bgp_peer_line(stripped, peers_by_ip, in_ipv4_family)
                continue

        return parsed

    def _parse_bgp_network(self, stripped: str) -> str | None:
        """Extract a network advertisement from a BGP sub-command."""
        match = re.match(
            r"^network\s+(\S+(?:\.\d+(?:\.\d+)?)?(?:\s+mask\s+\S+)?)",
            stripped,
        )
        return match.group(1).strip() if match else None

    def _parse_bgp_peer_line(
        self, stripped: str, peers_by_ip: dict, in_ipv4_family: bool
    ) -> None:
        """Parse a peer sub-command and update the peer dict."""
        ip_match = re.match(r"^peer\s+(\S+)", stripped)
        if not ip_match:
            return
        peer_ip = ip_match.group(1)
        peer = peers_by_ip.get(peer_ip)
        if not peer:
            return

        rest = stripped[len(f"peer {peer_ip}"):].strip()

        # description
        desc_match = re.match(r"^description\s+(.+)", rest)
        if desc_match:
            peer["description"] = desc_match.group(1).strip().strip('"')
            return

        # route-policy import/export
        rp_match = re.match(r"^route-policy\s+(\S+)\s+(import|export)", rest)
        if rp_match:
            policy_name = rp_match.group(1)
            direction = rp_match.group(2)
            if direction == "import":
                peer["route_policy_import"] = policy_name
            else:
                peer["route_policy_export"] = policy_name
            return

        # connect-interface
        ci_match = re.match(r"^connect-interface\s+(\S+)", rest)
        if ci_match:
            peer["connect_interface"] = ci_match.group(1)
            return

        # password / cipher / simple
        pw_match = re.match(
            r"^password\s+(cipher|simple)\s+\S+", rest
        )
        if pw_match:
            peer["has_password"] = True
            peer["password_type"] = pw_match.group(1)
            return
        if re.match(r"^password\s+\S+", rest):
            peer["has_password"] = True
            peer["password_type"] = "unknown"
            return

        # enable (only inside ipv4-family)
        if rest == "enable":
            peer["enabled"] = True
            return

    def _extract_static_routes(self, text: str) -> list:
        """Extract all ip route-static lines from configuration.

        VRP format:
            ip route-static {dest} {mask} {next-hop|NULL0}
                [preference {pref}] [tag {tag}] [description {text}]

        With vpn-instance:
            ip route-static vpn-instance {name} {dest} {mask} {next-hop} ...
        """
        routes = []
        for match in self.RE_ROUTE_STATIC.finditer(text):
            route_text = match.group(1).strip()
            route = {
                "raw": f"ip route-static {route_text}",
                "vpn_instance": None,
            }

            tokens = route_text.split()
            pos = 0

            # Check for vpn-instance
            if pos < len(tokens) and tokens[pos].lower() == "vpn-instance":
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

            # Keyword-value pairs
            while pos < len(tokens):
                kw = tokens[pos].lower()
                if kw == "preference" and pos + 1 < len(tokens):
                    pos += 1
                    route["preference"] = tokens[pos]
                elif kw == "tag" and pos + 1 < len(tokens):
                    pos += 1
                    route["tag"] = tokens[pos]
                elif kw == "description" and pos + 1 < len(tokens):
                    pos += 1
                    route["description"] = tokens[pos]
                pos += 1

            routes.append(route)

        return routes

    def _parse_vsi_block(self, block: dict) -> dict:
        """Extract structured data from a VSI block.

        VRP format:
            vsi NAME
             pwsignal ldp
              vsi-id <id>
             peer X.X.X.X
            #
        """
        header = block["header"]
        # Extract just the VSI name (first token after "vsi ")
        vsi_name = header[len("vsi "):].strip().split()[0]

        parsed = {
            "name": vsi_name,
            "vsi_id": None,
            "peers": [],
            "raw": block["raw"],
        }

        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue

            id_match = re.match(r"^vsi-id\s+(\d+)", stripped)
            if id_match:
                parsed["vsi_id"] = id_match.group(1)
                continue

            peer_match = re.match(r"^(?:peer|vpls)\s+(\S+)", stripped)
            if peer_match:
                peer_ip = peer_match.group(1)
                # Only add if it looks like an IP
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", peer_ip):
                    parsed["peers"].append(peer_ip)
                    continue

        return parsed

    def _parse_aaa_block(self, block: dict) -> dict:
        """Parse an AAA configuration block."""
        parsed = {
            "type": "aaa",
            "raw": block["raw"],
        }
        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue
            # Track schemes and domains referenced
            if "authentication-scheme" in stripped:
                parsed.setdefault("authentication_schemes", []).append(stripped)
            elif "authorization-scheme" in stripped:
                parsed.setdefault("authorization_schemes", []).append(stripped)
            elif "accounting-scheme" in stripped:
                parsed.setdefault("accounting_schemes", []).append(stripped)
            elif "domain" in stripped:
                parsed.setdefault("domains", []).append(stripped)
        return parsed

    def _parse_radius_block(self, block: dict) -> dict:
        """Parse a RADIUS server configuration block."""
        header = block["header"]
        # Extract server name/template
        # "radius-server group RADIUS-ISP" -> name="RADIUS-ISP"
        # "radius server RADIUS-BACKUP" -> name="RADIUS-BACKUP"
        parts = header.replace("radius-server", "").replace("radius server", "").strip()
        tokens = parts.split()
        # Skip "group" / "template" keyword if present
        name = ""
        for token in tokens:
            if token.lower() in ("group", "template"):
                continue
            name = token
            break
        if not name and tokens:
            name = tokens[0]
        parsed = {
            "name": name,
            "template": name,
            "type": "radius_server",
            "raw": block["raw"],
        }
        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue
            if "radius-server" in stripped and "authentication" in stripped:
                parsed["has_authentication"] = True
            elif "radius-server" in stripped and "accounting" in stripped:
                parsed["has_accounting"] = True
            if "ip" in stripped or "." in stripped:
                parsed.setdefault("lines", []).append(stripped)
        return parsed

    def _parse_ip_pool_block(self, block: dict) -> dict:
        """Parse an IP pool configuration block."""
        header = block["header"]
        pool_name = header[len("ip pool "):].strip() if header.startswith("ip pool") else ""
        parsed = {
            "name": pool_name,
            "type": "ip_pool",
            "gateway": None,
            "dns_servers": [],
            "raw": block["raw"],
        }
        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue
            if "gateway" in stripped:
                parts = stripped.split()
                for p in parts:
                    if p.count(".") == 3 and p.replace(".", "").isdigit():
                        parsed["gateway"] = p
            elif "dns-server" in stripped:
                parts = stripped.split()
                for p in parts:
                    if p.count(".") == 3 and p.replace(".", "").isdigit():
                        parsed["dns_servers"].append(p)
        return parsed

    def _parse_aaa_domain_block(self, block: dict) -> dict:
        """Parse an AAA domain configuration block."""
        header = block["header"]
        domain_name = header[len("domain "):].strip() if header.startswith("domain ") else ""
        parsed = {
            "name": domain_name,
            "type": "aaa_domain",
            "raw": block["raw"],
        }
        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue
            if "authentication-scheme" in stripped:
                parsed["authentication_scheme"] = stripped.split()[-1]
            elif "accounting-scheme" in stripped:
                parsed["accounting_scheme"] = stripped.split()[-1]
            elif "radius-server" in stripped:
                parsed["radius_server_group"] = stripped.split()[-1]
        return parsed

    def _parse_bas_block(self, block: dict) -> dict:
        """Parse a BAS configuration block."""
        parsed = {
            "type": "bas",
            "raw": block["raw"],
        }
        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue
            if "access-type" in stripped:
                parsed["access_type"] = stripped.replace("access-type", "").strip()
            elif "authentication-scheme" in stripped:
                parsed.setdefault("authentication_schemes", []).append(stripped)
            elif "accounting-scheme" in stripped:
                parsed.setdefault("accounting_schemes", []).append(stripped)
            elif "domain" in stripped:
                parsed.setdefault("domains", []).append(stripped)
        return parsed

    def _parse_generic_block(self, block: dict, block_type: str) -> dict:
        """Parse a generic block by storing its raw lines."""
        return {
            "type": block_type,
            "header": block["header"],
            "raw": block["raw"],
        }

    def _extract_bng_indicators(self, parsed_data: dict) -> list[dict]:
        """Scan parsed data for BNG-related keywords."""
        raw_text = parsed_data.get("raw", "").lower()
        indicators: list[dict] = []
        seen: set[str] = set()

        for keyword in self.BNG_INDICATOR_KEYWORDS:
            if keyword in raw_text and keyword not in seen:
                seen.add(keyword)
                indicators.append({
                    "keyword": keyword,
                    "confidence_weight": 0.15,
                })

        # Check for specific blocks
        if parsed_data.get("aaa"):
            indicators.append({
                "keyword": "aaa_block",
                "confidence_weight": 0.25,
            })
        if parsed_data.get("radius_servers"):
            indicators.append({
                "keyword": "radius_server_block",
                "confidence_weight": 0.20,
            })
        if parsed_data.get("ip_pools"):
            indicators.append({
                "keyword": "ip_pool_block",
                "confidence_weight": 0.20,
            })
        if parsed_data.get("aaa_domains"):
            indicators.append({
                "keyword": "aaa_domain_block",
                "confidence_weight": 0.20,
            })
        if parsed_data.get("bas_interfaces"):
            indicators.append({
                "keyword": "bas_block",
                "confidence_weight": 0.30,
            })

        return indicators

    # ── SNMP parser ─────────────────────────────────────────────────

    def _parse_snmp_line(self, line: str, snmp: dict) -> None:
        """Parse a single snmp-agent command line.

        Never stores real community strings or secrets — only flags.
        """
        snmp["enabled"] = True
        snmp["raw_lines"].append(line)

        lower = line.lower()

        # snmp-agent sys-info version
        if "sys-info version" in lower:
            ver_match = re.findall(r"v[123c]+", lower)
            for v in ver_match:
                if v not in snmp["versions"]:
                    snmp["versions"].append(v)

        # snmp-agent community — never store real value
        elif "community" in lower:
            entry = {
                "community_masked": True,
                "access": "unknown",
                "has_secret": True,
                "secret_type": "unknown",
                "acl_ref": None,
            }
            if " read " in lower:
                entry["access"] = "read"
            elif " write " in lower:
                entry["access"] = "write"
            # Detect cipher/simple
            if "cipher" in lower:
                entry["secret_type"] = "cipher"
            elif "simple" in lower:
                entry["secret_type"] = "simple"
            # ACL reference via acl keyword
            acl_m = re.search(r"\bacl\s+(\d+)", lower)
            if acl_m:
                entry["acl_ref"] = acl_m.group(1)
                if acl_m.group(1) not in snmp["acl_refs"]:
                    snmp["acl_refs"].append(acl_m.group(1))
            snmp["communities"].append(entry)

        # snmp-agent target-host trap
        elif "target-host trap" in lower:
            trap = {"ip": None, "security_name_masked": True, "version": None}
            ip_m = re.search(r"address\s+udp-domain\s+(\S+)", lower)
            if ip_m:
                trap["ip"] = ip_m.group(1)
            ver_m = re.search(r"(v1|v2c|v3)", lower)
            if ver_m:
                trap["version"] = ver_m.group(1)
            snmp["trap_hosts"].append(trap)

        # snmp-agent usm-user
        elif "usm-user" in lower:
            user_m = re.search(r"usm-user\s+(?:v3\s+)?(\S+)", lower)
            user_entry = {
                "name": user_m.group(1) if user_m else "unknown",
                "has_secret": False,
                "auth_mode": None,
                "priv_mode": None,
            }
            # Don't store auth/priv keys, just detect modes
            if "authentication-mode" in lower:
                user_entry["has_secret"] = True
                auth_m = re.search(r"authentication-mode\s+(\S+)", lower)
                if auth_m:
                    user_entry["auth_mode"] = auth_m.group(1)
            if "privacy-mode" in lower:
                user_entry["has_secret"] = True
                priv_m = re.search(r"privacy-mode\s+(\S+)", lower)
                if priv_m:
                    user_entry["priv_mode"] = priv_m.group(1)
            # Check if already exists
            existing = [u for u in snmp["users"] if u["name"] == user_entry["name"]]
            if not existing:
                snmp["users"].append(user_entry)

        # snmp-agent group
        elif " group " in lower:
            group_m = re.search(r"group\s+v3\s+(\S+)", lower)
            if group_m:
                entry = {"name": group_m.group(1), "level": None}
                for level in ("privacy", "auth", "noauth"):
                    if level in lower:
                        entry["level"] = level
                        break
                if entry not in snmp["groups"]:
                    snmp["groups"].append(entry)

        # snmp-agent acl reference
        elif " acl " in lower:
            acl_m = re.search(r"acl\s+(\d+)", lower)
            if acl_m and acl_m.group(1) not in snmp["acl_refs"]:
                snmp["acl_refs"].append(acl_m.group(1))

        # snmp-agent mib-view
        elif "mib-view" in lower:
            if "mib_view" not in snmp:
                snmp["mib_view"] = True

    # ── NTP parser ─────────────────────────────────────────────────

    def _parse_ntp_line(self, line: str, ntp: dict) -> None:
        """Parse a single ntp-service command line."""
        ntp["enabled"] = True
        ntp["raw_lines"].append(line)

        lower = line.lower()

        # ntp-service unicast-server
        if "unicast-server" in lower:
            server = {"ip": None, "preference": False, "source": None}
            parts = lower.split()
            for i, p in enumerate(parts):
                if p == "unicast-server" and i + 1 < len(parts):
                    ip_candidate = parts[i + 1]
                    if ip_candidate.count(".") == 3:
                        server["ip"] = ip_candidate
                if p == "preference":
                    server["preference"] = True
                if p == "source-interface" and i + 1 < len(parts):
                    server["source"] = parts[i + 1]
            if server["ip"]:
                ntp["servers"].append(server)

        # ntp-service source-interface
        elif "source-interface" in lower:
            # Extract preserving original case
            raw_lower = line.lower()
            idx = raw_lower.find("source-interface")
            if idx >= 0:
                rest = line[idx + len("source-interface"):].strip()
                if rest:
                    ntp["source_interface"] = rest

        # ntp-service authentication enable
        elif "authentication enable" in lower:
            ntp["authentication_enabled"] = True

    # ── Syslog/info-center parser ──────────────────────────────────

    def _parse_syslog_line(self, line: str, syslog: dict) -> None:
        """Parse a single info-center command line."""
        syslog["enabled"] = True
        syslog["raw_lines"].append(line)

        lower = line.lower()

        # info-center loghost
        if "loghost" in lower or "log host" in lower:
            entry = {"ip": None, "facility": None}
            ip_m = re.search(r"loghost\s+(\S+)", lower)
            if not ip_m:
                ip_m = re.search(r"log\s+host\s+(\S+)", lower)
            if ip_m:
                entry["ip"] = ip_m.group(1)
            facility_m = re.search(r"facility\s+(\S+)", lower)
            if facility_m:
                entry["facility"] = facility_m.group(1)
                if facility_m.group(1) not in syslog["facilities"]:
                    syslog["facilities"].append(facility_m.group(1))
            if entry["ip"]:
                syslog["log_hosts"].append(entry)

        # info-center timestamp
        elif "timestamp" in lower:
            if "timestamp" not in syslog:
                syslog["timestamp"] = lower.split("timestamp", 1)[1].strip()

    # ── VTY/User-interface parser ──────────────────────────────────

    def _parse_vty_block(self, block: dict) -> dict:
        """Parse a user-interface vty block."""
        header = block["header"]
        parsed = {
            "type": "vty",
            "linespec": header.replace("user-interface", "").strip(),
            "authentication_mode": None,
            "protocol_inbound": None,
            "idle_timeout": None,
            "acl_inbound": None,
            "acl_outbound": None,
            "raw": block["raw"],
        }

        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue

            lower = stripped.lower()
            if lower.startswith("authentication-mode"):
                parsed["authentication_mode"] = stripped.split(None, 1)[1].strip() if len(stripped.split(None, 1)) > 1 else None
            elif lower.startswith("protocol inbound"):
                parsed["protocol_inbound"] = stripped.split(None, 2)[2].strip() if len(stripped.split(None, 2)) > 2 else None
            elif lower.startswith("idle-timeout"):
                parsed["idle_timeout"] = stripped.split(None, 1)[1].strip() if len(stripped.split(None, 1)) > 1 else None
            elif lower.startswith("acl ") and "inbound" in lower:
                acl_m = re.search(r"acl\s+(\d+)\s+inbound", lower)
                if acl_m:
                    parsed["acl_inbound"] = acl_m.group(1)
            elif lower.startswith("acl ") and "outbound" in lower:
                acl_m = re.search(r"acl\s+(\d+)\s+outbound", lower)
                if acl_m:
                    parsed["acl_outbound"] = acl_m.group(1)

        return parsed

    # ── SSH parser ─────────────────────────────────────────────────

    def _parse_ssh_line(self, line: str, ssh: dict) -> None:
        """Parse a single SSH/stelnet command line."""
        ssh["raw_lines"].append(line)
        lower = line.lower()

        if "stelnet server enable" in lower or "ssh server" in lower:
            ssh["enabled"] = True
        elif lower.startswith("ssh user") or lower.startswith("stelnet user"):
            user_m = re.search(r"(?:ssh|stelnet)\s+user\s+(\S+)", lower)
            if user_m:
                username = user_m.group(1)
                existing = [u for u in ssh["users"] if u["name"] == username]
                if existing:
                    user_entry = existing[0]
                else:
                    user_entry = {"name": username, "authentication_type": None, "service_type": None}
                    ssh["users"].append(user_entry)
                if "authentication-type" in lower:
                    auth_m = re.search(r"authentication-type\s+(\S+)", lower)
                    if auth_m:
                        user_entry["authentication_type"] = auth_m.group(1)
                if "service-type" in lower:
                    svc_m = re.search(r"service-type\s+(\S+)", lower)
                    if svc_m:
                        user_entry["service_type"] = svc_m.group(1)

    # ── Local-user parser (from AAA or standalone) ─────────────────

    def _parse_local_user_line(self, line: str, result: dict) -> None:
        """Parse a standalone local-user command line."""
        self._add_local_user_entry(line, result["local_users"])

    def _extract_all_local_users(self, result: dict) -> None:
        """Extract local-user entries from the entire raw config text.

        Scans the raw config for any line starting with 'local-user',
        whether inside AAA blocks or standalone.
        Never stores real passwords — only flags.
        """
        raw_text = result.get("raw", "")
        if not raw_text:
            return
        for raw_line in raw_text.splitlines():
            stripped = raw_line.strip()
            if stripped.startswith("local-user"):
                self._add_local_user_entry(stripped, result["local_users"])

    def _extract_aaa_sub_blocks(self, result: dict) -> None:
        """Extract AAA sub-blocks (auth/acct schemes, domains, bas) from raw text.

        With the indentation fix, sub-commands inside AAA are no longer
        separate blocks. This method re-extracts them from the raw text.
        """
        raw_text = result.get("raw", "")
        if not raw_text:
            return
        for raw_line in raw_text.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped in ("#", "!"):
                continue
            lower = stripped.lower()
            if lower.startswith("authentication-scheme "):
                result["auth_schemes"].append({
                    "type": "auth_scheme",
                    "header": stripped,
                    "raw": stripped,
                })
            elif lower.startswith("accounting-scheme "):
                result["acct_schemes"].append({
                    "type": "acct_scheme",
                    "header": stripped,
                    "raw": stripped,
                })
            elif lower.startswith("domain ") and not lower.startswith("domain default"):
                result["aaa_domains"].append({
                    "name": stripped[len("domain "):].strip(),
                    "type": "aaa_domain",
                    "raw": stripped,
                })
                # Also capture domain default
            elif lower.startswith("domain default"):
                result["aaa_domains"].append({
                    "name": "default",
                    "type": "aaa_domain",
                    "raw": stripped,
                })
            elif lower in ("bas",):
                result["bas_interfaces"].append({
                    "type": "bas",
                    "raw": stripped,
                })

    def _add_local_user_entry(self, line: str, users: list) -> None:
        """Parse a local-user command line and add to users list.

        Never stores the real password — only flags.
        """
        lower = line.lower()
        if not lower.startswith("local-user"):
            return

        name_m = re.search(r"local-user\s+(\S+)", lower)
        if not name_m:
            return
        username = name_m.group(1)

        # Find or create user entry
        existing = [u for u in users if u["name"] == username]
        if existing:
            entry = existing[0]
        else:
            entry = {
                "name": username,
                "has_password": False,
                "password_type": None,
                "privilege_level": None,
                "service_types": [],
            }
            users.append(entry)

        # password — never store real secret
        if "password" in lower:
            entry["has_password"] = True
            if "irreversible-cipher" in lower:
                entry["password_type"] = "irreversible-cipher"
            elif "cipher" in lower:
                entry["password_type"] = "cipher"
            elif "simple" in lower:
                entry["password_type"] = "simple"
            else:
                entry["password_type"] = "unknown"

        # privilege level
        if "privilege level" in lower:
            priv_m = re.search(r"privilege\s+level\s+(\d+)", lower)
            if priv_m:
                entry["privilege_level"] = int(priv_m.group(1))

        # service-type
        if "service-type" in lower:
            svc_m = re.search(r"service-type\s+(.+)", lower)
            if svc_m:
                services = svc_m.group(1).split()
                for s in services:
                    if s not in entry["service_types"]:
                        entry["service_types"].append(s)

    # ── Management access summary ──────────────────────────────────

    def _build_management_access(self, result: dict) -> dict:
        """Build a summary of management access configuration."""
        ma = {
            "has_local_users": len(result.get("local_users", [])) > 0,
            "has_vty": len(result.get("vty_lines", [])) > 0,
            "has_ssh": result.get("ssh", {}).get("enabled", False),
            "has_telnet": False,
            "has_acl_on_vty": False,
        }

        # Detect telnet from VTY lines
        for vty in result.get("vty_lines", []):
            proto = vty.get("protocol_inbound", "")
            if proto and "telnet" in proto.lower():
                ma["has_telnet"] = True
            if vty.get("acl_inbound"):
                ma["has_acl_on_vty"] = True

        return ma

    # ── ACL parser ──────────────────────────────────────────────────

    def _parse_as_path_filter_block(self, block: dict) -> dict | None:
        """Parse an ip as-path-filter block.

        Huawei format:
            ip as-path-filter 10 permit ^64520$
            ip as-path-filter 10 deny .*
        """
        header = block["header"]
        lines = block.get("lines", [])
        full_lines = lines  # lines already includes the header

        m = re.match(r"ip\s+as-path-filter\s+(\S+)", header, re.IGNORECASE)
        if not m:
            return None
        name = m.group(1)

        rules = []
        for line in full_lines:
            stripped = line.strip()
            rm = re.match(
                r"(?:ip\s+as-path-filter\s+\S+(?:\s+index\s+\d+)?\s+)?"
                r"(deny|permit)\s+(.+)",
                stripped, re.IGNORECASE
            )
            if rm:
                rules.append({
                    "action": rm.group(1),
                    "pattern": rm.group(2).strip(),
                    "raw": stripped,
                })

        if not rules:
            return None

        return {
            "name": name,
            "rules": rules,
            "raw_lines": full_lines,
            "raw": block.get("raw", ""),
        }

    def _parse_community_filter_block(self, block: dict) -> dict | None:
        """Parse an ip community-filter block.

        Huawei format:
            ip community-filter 20 permit 65000:100
            ip community-filter basic CLIENTE-COMM permit 65000:200
            ip community-filter advanced COMM-ADV permit ^65000:
        """
        header = block["header"]
        lines = block.get("lines", [])
        full_lines = lines  # lines already includes the header

        m = re.match(
            r"ip\s+community-filter\s+(?:basic|advanced)?\s*(\S+)",
            header, re.IGNORECASE
        )
        if not m:
            return None
        name = m.group(1)

        # Determine type
        filter_type = "basic"
        hl = header.lower()
        if " advanced " in hl or hl.startswith("ip community-filter advanced"):
            filter_type = "advanced"
        elif " basic " in hl or hl.startswith("ip community-filter basic"):
            filter_type = "basic"

        rules = []
        for line in full_lines:
            stripped = line.strip()
            rm = re.match(
                r"(?:ip\s+community-filter\s+(?:(?:basic|advanced)\s+)?\S+(?:\s+index\s+\d+)?\s+)?"
                r"(deny|permit)\s+(.+)",
                stripped, re.IGNORECASE
            )
            if rm:
                idx_m = re.search(r"index\s+(\d+)", stripped, re.IGNORECASE)
                rules.append({
                    "index": int(idx_m.group(1)) if idx_m else None,
                    "action": rm.group(1),
                    "value": rm.group(2).strip(),
                    "raw": stripped,
                })

        if not rules:
            return None

        return {
            "name": name,
            "type": filter_type,
            "rules": rules,
            "raw_lines": full_lines,
            "raw": block.get("raw", ""),
        }

    def _parse_prefix_list_block(self, block: dict) -> dict | None:
        """Parse an ip prefix-list block.

        Huawei format:
            ip ip-prefix NAME index 10 permit 10.0.0.0 8
            ip ip-prefix NAME index 20 deny 0.0.0.0 0 le 32
            ip ip-prefix NAME index 30 permit 0.0.0.0 0 ge 16 le 24
        """
        header = block["header"]
        raw_lines = block.get("lines", [])
        full_lines = raw_lines  # raw_lines already includes the header

        # Extract name from header: "ip ip-prefix NAME ..."
        m = re.match(r"ip\s+(?:prefix-list|ip-prefix)\s+(\S+)", header, re.IGNORECASE)
        if not m:
            return None
        name = m.group(1)

        rules = []
        for line in full_lines:
            stripped = line.strip()
            # Each line is self-contained: "ip ip-prefix NAME index N permit|deny PREFIX MASK [ge|le]"
            rule_match = re.match(
                r"(?:ip\s+(?:prefix-list|ip-prefix)\s+\S+\s+)?"
                r"index\s+(\d+)\s+(permit|deny)\s+"
                r"(\S+)\s+(\d+)"
                r"(?:\s+greater-equal\s+(\d+))?"
                r"(?:\s+less-equal\s+(\d+))?",
                stripped, re.IGNORECASE
            )
            if rule_match:
                rules.append({
                    "index": int(rule_match.group(1)),
                    "action": rule_match.group(2),
                    "prefix": rule_match.group(3),
                    "mask_length": int(rule_match.group(4)),
                    "greater_equal": int(rule_match.group(5)) if rule_match.group(5) else None,
                    "less_equal": int(rule_match.group(6)) if rule_match.group(6) else None,
                    "raw": stripped,
                })

        if not rules:
            return None

        return {
            "name": name,
            "rules": sorted(rules, key=lambda r: r["index"]),
            "raw_lines": full_lines,
            "raw": block.get("raw", ""),
        }

    def _parse_route_policy_block(self, block: dict) -> dict | None:
        """Parse a route-policy block.

        Huawei format:
            route-policy EXPORT-CLIENTE permit node 10
             if-match ip-prefix CLIENTE-X
             apply community 65000:100 additive
            #
        """
        header = block["header"]
        lines = block.get("lines", [])

        # route-policy <name> permit|deny node <N>
        m = re.match(
            r"route-policy\s+(\S+)\s+(permit|deny)",
            header, re.IGNORECASE
        )
        if not m:
            return None
        name = m.group(1)
        node_action = m.group(2)

        node_m = re.search(r"node\s+(\d+)", header, re.IGNORECASE)
        node_number = int(node_m.group(1)) if node_m else 0

        if_matches = []
        apply_actions = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue
            # Skip the header line if it appears in lines (block reuse)
            if stripped.lower().startswith("route-policy"):
                continue
            # if-match patterns
            im = re.match(r"if-match\s+ip-prefix\s+(\S+)", stripped, re.IGNORECASE)
            if im:
                if_matches.append({"type": "ip-prefix", "name": im.group(1), "raw": stripped})
                continue
            im = re.match(r"if-match\s+acl\s+(\S+)", stripped, re.IGNORECASE)
            if im:
                if_matches.append({"type": "acl", "name": im.group(1), "raw": stripped})
                continue
            im = re.match(r"if-match\s+as-path-filter\s+(\S+)", stripped, re.IGNORECASE)
            if im:
                if_matches.append({"type": "as-path-filter", "name": im.group(1), "raw": stripped})
                continue
            im = re.match(r"if-match\s+community-filter\s+(\S+)", stripped, re.IGNORECASE)
            if im:
                if_matches.append({"type": "community-filter", "name": im.group(1), "raw": stripped})
                continue
            # apply patterns
            ap = re.match(r"apply\s+local-preference\s+(\S+)", stripped, re.IGNORECASE)
            if ap:
                apply_actions.append({"type": "local-preference", "value": ap.group(1), "raw": stripped})
                continue
            ap = re.match(r"apply\s+community\s+(.+)", stripped, re.IGNORECASE)
            if ap:
                apply_actions.append({"type": "community", "value": ap.group(1).strip(), "raw": stripped})
                continue
            ap = re.match(r"apply\s+cost\s+(\S+)", stripped, re.IGNORECASE)
            if ap:
                apply_actions.append({"type": "cost", "value": ap.group(1), "raw": stripped})
                continue
            ap = re.match(r"apply\s+med\s+(\S+)", stripped, re.IGNORECASE)
            if ap:
                apply_actions.append({"type": "med", "value": ap.group(1), "raw": stripped})
                continue
            ap = re.match(r"apply\s+ip-address\s+next-hop\s+(\S+)", stripped, re.IGNORECASE)
            if ap:
                apply_actions.append({"type": "next-hop", "value": ap.group(1), "raw": stripped})
                continue
            # Unknown → keep raw
            if_matches.append({"type": "unknown", "raw": stripped})

        return {
            "name": name,
            "node": node_number,
            "action": node_action,
            "if_match": if_matches,
            "apply": apply_actions,
            "raw_lines": [header] + lines,
            "raw": block.get("raw", ""),
        }

    def _parse_acl_block(self, block: dict) -> dict | None:
        """Parse an ACL definition block.

        Huawei format:
            acl number <N>
             rule <N> permit/deny ...
            acl name <NAME> [basic|advanced]
             rule <N> permit/deny ...
        """
        header = block["header"]
        lower = header.lower()

        acl_entry: dict = {
            "name": "",
            "number": "",
            "type": "basic",
            "rules": [],
            "header": header,
            "raw": block["raw"],
        }

        num_match = re.match(r"acl\s+number\s+(\d+)", header, re.IGNORECASE)
        name_match = re.match(r"acl\s+name\s+(\S+)", header, re.IGNORECASE)

        if num_match:
            acl_entry["number"] = num_match.group(1)
            acl_entry["name"] = acl_entry["number"]
        elif name_match:
            acl_entry["name"] = name_match.group(1)
            rest = header[len(f"acl name {acl_entry['name']}"):].strip()
            acl_entry["type"] = rest if rest else "basic"
        else:
            return None

        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped in ("#",):
                continue
            if stripped.startswith("rule "):
                rule: dict = {"raw": stripped, "action": None, "source": None}
                rl = stripped.lower()
                if "permit" in rl:
                    rule["action"] = "permit"
                elif "deny" in rl:
                    rule["action"] = "deny"
                src_match = re.search(r"source\s+(\S+)", stripped)
                if src_match:
                    rule["source"] = src_match.group(1)
                acl_entry["rules"].append(rule)

        return acl_entry

    def _enrich_acl_references(self, result: dict) -> None:
        """Tie ACL references in SNMP/VTY to defined ACLs.

        Adds enriched metadata so detectors can check whether
        a referenced ACL is actually defined in the config.
        """
        acls = result.get("acls", [])
        defined_numbers = {a["number"] for a in acls if a["number"]}
        defined_names = {a["name"] for a in acls if a["name"]}

        # Enrich SNMP ACL refs
        snmp = result.get("snmp", {})
        enriched = []
        for ref in snmp.get("acl_refs", []):
            enriched.append({
                "ref": ref,
                "exists": ref in defined_numbers or ref in defined_names,
            })
        snmp["acl_refs_enriched"] = enriched

        # Enrich VTY ACL refs
        for vty in result.get("vty_lines", []):
            for direction in ("acl_inbound", "acl_outbound"):
                ref = vty.get(direction)
                if ref:
                    vty[f"{direction}_defined"] = ref in defined_numbers or ref in defined_names

    @staticmethod
    def _classify_interface(name: str) -> str:
        """Classify interface type."""
        name_lower = name.lower()
        if name_lower.startswith("eth-trunk"):
            return "eth-trunk"
        if name_lower.startswith("loopback"):
            return "loopback"
        if name_lower.startswith("vlanif"):
            return "vlanif"
        if name_lower.startswith("null"):
            return "null"
        if name_lower.startswith("nve"):
            return "nve"
        if "." in name_lower:
            # Could be subinterface of any physical type
            if any(
                name_lower.startswith(p)
                for p in [
                    "gigabitethernet",
                    "xgigabitethernet",
                    "40ge",
                    "100ge",
                    "ethernet",
                    "serial",
                    "pos",
                ]
            ):
                return "physical_subinterface"
            return "subinterface"
        # Physical interfaces
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
