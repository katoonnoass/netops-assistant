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
    RE_IPV6_ROUTE_STATIC = re.compile(r"^ipv6\s+route-static\s+(.+?)$", re.MULTILINE)
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
        # VPN/VRF blocks
        "ip vpn-instance",
        # QoS / Traffic Policy blocks
        "traffic classifier",
        "traffic behavior",
        "traffic policy",
        "ospfv3",
        "ip ipv6-prefix",
        "qos-profile",
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
            "isis": [],
            "mpls": {
                "enabled": False,
                "lsr_id": None,
                "te_enabled": False,
                "raw_lines": [],
            },
            "mpls_ldp": {
                "enabled": False,
                "graceful_restart": False,
                "remote_peers": [],
                "raw_lines": [],
            },
            "vpn_instances": [],
            "qos": {
                "traffic_classifiers": [],
                "traffic_behaviors": [],
                "traffic_policies": [],
                "qos_profiles": [],
            },
            "nat": {
                "address_groups": [],
                "outbound_rules": [],
                "static_rules": [],
                "server_rules": [],
                "alg": [],
            },
            "ipv6_static_routes": [],
            "ipv6_prefix_lists": [],
            "ospfv3": [],
            "bgp_ipv6": [],
            "vpnv6": [],
            "vpn_instances_ipv6": [],
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
            elif block["type"] == "vpn_instance":
                parsed = self._parse_vpn_instance_block(block)
                if parsed:
                    result["vpn_instances"].append(parsed)
            elif block["type"] == "nat":
                self._parse_nat_line(block["header"], result)
            elif block["type"] == "traffic_classifier":
                parsed = self._parse_traffic_classifier_block(block)
                if parsed:
                    result["qos"]["traffic_classifiers"].append(parsed)
            elif block["type"] == "traffic_behavior":
                parsed = self._parse_traffic_behavior_block(block)
                if parsed:
                    result["qos"]["traffic_behaviors"].append(parsed)
            elif block["type"] == "traffic_policy":
                parsed = self._parse_traffic_policy_block(block)
                if parsed:
                    result["qos"]["traffic_policies"].append(parsed)
            elif block["type"] == "qos_profile":
                parsed = self._parse_qos_profile_block(block)
                if parsed:
                    result["qos"]["qos_profiles"].append(parsed)
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
            elif block["type"] == "isis":
                parsed = self._parse_isis_block(block)
                if parsed:
                    result["isis"].append(parsed)
            elif block["type"] == "ospfv3":
                parsed = self._parse_ospfv3_block(block)
                if parsed:
                    result["ospfv3"].append(parsed)
            elif block["type"] == "mpls":
                self._parse_mpls_block(block, result)

        # Post-process: extract ISIS/MPLS/LDP from interfaces
        self._enrich_interfaces_core(result)

        result["static_routes"] = self._extract_static_routes(text)
        result["ipv6_static_routes"] = self._extract_ipv6_static_routes(text)
        result["bng_indicators"] = self._extract_bng_indicators(result)

        # Post-process: extract local-users from raw text
        self._extract_all_local_users(result)

        # Post-process: extract AAA sub-blocks (auth schemes, domains, etc.)
        self._extract_aaa_sub_blocks(result)

        # Build management_access summary
        result["management_access"] = self._build_management_access(result)

        # Post-process: tie ACL references to definitions in SNMP data
        self._enrich_acl_references(result)

        # Post-process: extract NAT from interfaces into global NAT dict
        self._extract_interface_nat(result)

        # Merge duplicate interfaces by name (same name in multiple blocks)
        self._merge_interfaces_by_name(result)

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

            # Handle non-indented '#' as block separator
            if stripped == "#" and not is_indented:
                if current_block:
                    blocks.append(self._finalize_block(current_block))
                    current_block = None
                continue

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
        if header_lower.startswith("ip ipv6-prefix"):
            return "prefix-list"
        if header_lower.startswith("ip ip-prefix"):
            return "prefix-list"
        if header_lower.startswith("ip as-path-filter"):
            return "as-path-filter"
        if header_lower.startswith("ip community-filter"):
            return "community-filter"
        if header_lower.startswith("ospfv3"):
            return "ospfv3"
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
        if header_lower.startswith("ip vpn-instance"):
            return "vpn_instance"
        if header_lower.startswith("nat "):
            return "nat"
        if header_lower.startswith("traffic classifier"):
            return "traffic_classifier"
        if header_lower.startswith("traffic behavior"):
            return "traffic_behavior"
        if header_lower.startswith("traffic policy"):
            return "traffic_policy"
        if header_lower.startswith("qos-profile"):
            return "qos_profile"
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
            "vpn_instance": None,
            "is_vrf_interface": False,
            "traffic_policies_applied": [],
            "qos_profiles_applied": [],
            "qos_car": [],
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

            elif stripped.startswith("ip binding vpn-instance "):
                vpn_name = stripped[len("ip binding vpn-instance "):].strip()
                parsed["vpn_instance"] = vpn_name
                parsed["is_vrf_interface"] = True

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

            # ── NAT per-interface ──────────────────────────────────
            if stripped.startswith("nat outbound"):
                parsed.setdefault("nat_outbound", []).append(stripped)
                parsed["has_nat"] = True
                continue
            if stripped.startswith("nat server"):
                parsed.setdefault("nat_server", []).append(stripped)
                parsed["has_nat"] = True
                continue
            if stripped.startswith("nat static"):
                parsed.setdefault("nat_static", []).append(stripped)
                parsed["has_nat"] = True
                continue
            if stripped.startswith("nat alg"):
                parsed.setdefault("nat_alg", []).append(stripped)
                parsed["has_nat"] = True
                continue

            # ── BAS per-interface ──────────────────────────────────
            if stripped.startswith("user-vlan "):
                uv = stripped[len("user-vlan "):].strip()
                qm = re.match(r"(\d+)\s+qinq\s+(\d+)", uv)
                if qm:
                    parsed["user_vlan"] = qm.group(1)
                    parsed["qinq_vlan"] = qm.group(2)
                else:
                    parsed["user_vlan"] = uv.split()[0] if uv else uv
            if stripped.startswith("bas"):
                parsed["bas"] = {"enabled": True}
            # BAS sub-commands (only relevant if bas is enabled)
            if parsed.get("bas") and parsed["bas"].get("enabled"):
                if stripped.startswith("access-type "):
                    at = stripped[len("access-type "):].strip()
                    parsed["bas"]["access_type"] = at.split()[0]
                    # Check for default-domain on the same line
                    dd = re.match(r".*default-domain\s+authentication\s+(\S+)", stripped, re.I)
                    if dd:
                        parsed["bas"]["default_domain"] = dd.group(1)
                    pd = re.match(r".*default-domain\s+pre-authentication\s+(\S+)", stripped, re.I)
                    if pd:
                        parsed["bas"]["pre_authentication_domain"] = pd.group(1)
                elif stripped.startswith("authentication-method "):
                    parsed["bas"]["authentication_method"] = stripped[len("authentication-method "):].strip()
                elif stripped.startswith("default-domain"):
                    dd = re.match(r"default-domain\s+authentication\s+(\S+)", stripped, re.I)
                    if dd:
                        parsed["bas"]["default_domain"] = dd.group(1)
                    pd = re.match(r"default-domain\s+pre-authentication\s+(\S+)", stripped, re.I)
                    if pd:
                        parsed["bas"]["pre_authentication_domain"] = pd.group(1)
                elif stripped.startswith("accounting-copy"):
                    ac = re.match(r"accounting-copy\s+radius-server\s+group\s+(\S+)", stripped, re.I)
                    if ac:
                        parsed["bas"]["accounting_copy_radius_group"] = ac.group(1)
                elif stripped == "ip-trigger":
                    parsed["bas"]["ip_trigger"] = True
                elif stripped == "arp-trigger":
                    parsed["bas"]["arp_trigger"] = True
                elif stripped == "ipv6-trigger":
                    parsed["bas"]["ipv6_trigger"] = True
            # Backward compat: also set top-level triggers (for non-BAS interfaces)
            if stripped == "ip-trigger":
                parsed["ip_trigger"] = True
            if stripped == "arp-trigger":
                parsed["arp_trigger"] = True
            if stripped == "ipv6-trigger":
                parsed["ipv6_trigger"] = True

            # ── QoS / Traffic Policy per-interface ─────────────────
            tp_match = re.match(
                r"^traffic-policy\s+(\S+)\s+(inbound|outbound)",
                stripped, re.IGNORECASE
            )
            if tp_match:
                parsed["traffic_policies_applied"].append({
                    "name": tp_match.group(1),
                    "direction": tp_match.group(2),
                })
                continue

            qp_match = re.match(
                r"^qos-profile\s+(\S+)\s+(inbound|outbound)",
                stripped, re.IGNORECASE
            )
            if qp_match:
                parsed["qos_profiles_applied"].append({
                    "name": qp_match.group(1),
                    "direction": qp_match.group(2),
                })
                continue

            # ── IPv6 per-interface ───────────────────────────────────
            if stripped == "ipv6 enable":
                parsed["ipv6_enabled"] = True
                continue
            if stripped.startswith("ipv6 address auto link-local"):
                parsed["ipv6_link_local_auto"] = True
                continue
            if stripped.startswith("ipv6 address auto global"):
                parsed["ipv6_global_auto"] = True
                continue
            v6_ll = re.match(r"^ipv6 address (\S+?)(?:/(\d+))?\s+link-local", stripped)
            if v6_ll:
                addr = v6_ll.group(1)
                pl = int(v6_ll.group(2)) if v6_ll.group(2) else None
                parsed.setdefault("ipv6_link_local_addresses", []).append({
                    "address": addr,
                    "prefix_length": pl,
                    "raw": stripped,
                })
                continue
            v6_addr = re.match(r"^ipv6 address (\S+)/(\d+)", stripped)
            if v6_addr:
                parsed.setdefault("ipv6_addresses", []).append({
                    "address": v6_addr.group(1),
                    "prefix_length": int(v6_addr.group(2)),
                    "raw": stripped,
                })
                continue
            v6_addr_sep = re.match(r"^ipv6 address (\S+)\s+(\d+)", stripped)
            if v6_addr_sep and "auto" not in stripped and "link-local" not in stripped:
                parsed.setdefault("ipv6_addresses", []).append({
                    "address": v6_addr_sep.group(1),
                    "prefix_length": int(v6_addr_sep.group(2)),
                    "raw": stripped,
                })
                continue

            # ── OSPFv3 per-interface ──────────────────────────────
            ov3 = re.match(r"^ospfv3\s+(\S+)\s+area\s+(\S+)", stripped)
            if ov3:
                parsed["ospfv3_enabled"] = True
                parsed["ospfv3_process_id"] = ov3.group(1)
                parsed["ospfv3_area"] = ov3.group(2)
                continue

            # ── ISIS IPv6 per-interface ───────────────────────────
            v6_isis = re.match(r"^isis\s+ipv6\s+enable\s+(\S+)", stripped)
            if v6_isis:
                parsed["isis_ipv6_enabled"] = True
                parsed["isis_ipv6_process_id"] = v6_isis.group(1)
                continue
            v6_isis_cost = re.match(r"^isis\s+ipv6\s+cost\s+(\d+)", stripped)
            if v6_isis_cost:
                parsed["isis_ipv6_cost"] = int(v6_isis_cost.group(1))
                continue

            qcar_match = re.match(
                r"^qos\s+car\s+(inbound|outbound)\s+cir\s+(\d+)(.*)",
                stripped, re.IGNORECASE
            )
            if qcar_match:
                qcar = {
                    "direction": qcar_match.group(1),
                    "cir": int(qcar_match.group(2)),
                }
                rest = qcar_match.group(3)
                pir_m = re.search(r"pir\s+(\d+)", rest, re.IGNORECASE)
                if pir_m:
                    qcar["pir"] = int(pir_m.group(1))
                qcar["raw"] = stripped
                parsed["qos_car"].append(qcar)
                continue

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

    def _parse_ospfv3_block(self, block: dict) -> dict | None:
        """Parse an OSPFv3 block."""
        header = block["header"]
        m = re.match(r"^ospfv3\s+(\S+)", header)
        if not m:
            return None
        parsed = {
            "process_id": m.group(1),
            "router_id": None,
            "raw_lines": block["lines"],
        }
        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue
            if stripped.startswith("router-id"):
                parsed["router_id"] = stripped[len("router-id "):].strip()
        return parsed

    def _parse_isis_block(self, block: dict) -> dict | None:
        """Parse an ISIS configuration block.

        Huawei VRP format:
            isis 1
             is-level level-2
             cost-style wide
             network-entity 49.0001.0100.0000.0001.00
             import-route direct
             import-route static
            #

        Returns:
            dict with keys: process_id, vpn_instance, is_level,
            cost_style, network_entity, import_routes, raw_lines.
        """
        header = block["header"]
        m = re.match(r"isis\s+(\S+)", header, re.IGNORECASE)
        if not m:
            return None
        process_id = m.group(1)

        parsed = {
            "process_id": process_id,
            "vpn_instance": None,
            "is_level": None,
            "cost_style": None,
            "network_entity": None,
            "import_routes": [],
            "raw_lines": block.get("lines", []),
            "raw": block.get("raw", ""),
        }

        # Check for vpn-instance in the header (e.g. "isis 2 vpn-instance CLIENTE-A")
        vpn_m = re.search(r"vpn-instance\s+(\S+)", header, re.IGNORECASE)
        if vpn_m:
            parsed["vpn_instance"] = vpn_m.group(1)

        for line in block.get("lines", [])[1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue
            sl = stripped.lower()

            if sl.startswith("is-level"):
                parsed["is_level"] = stripped[len("is-level"):].strip()
            elif sl.startswith("cost-style"):
                parsed["cost_style"] = stripped[len("cost-style"):].strip()
            elif sl.startswith("network-entity"):
                parsed["network_entity"] = stripped[len("network-entity"):].strip()
            elif sl.startswith("import-route"):
                route_val = stripped[len("import-route"):].strip()
                if route_val and route_val not in parsed["import_routes"]:
                    parsed["import_routes"].append(route_val)
            elif sl.startswith("vpn-instance"):
                parsed["vpn_instance"] = stripped[len("vpn-instance"):].strip()

        return parsed

    def _parse_mpls_block(self, block: dict, result: dict) -> None:
        """Parse an MPLS or MPLS LDP configuration block.

        Handles:
            mpls lsr-id 10.255.0.1
            mpls
             mpls te
            #
            mpls ldp
             graceful-restart
            #
            mpls ldp remote-peer PEER-1
             remote-ip 10.255.0.2
            #
        """
        header = block["header"]
        lower = header.lower()

        # MPLS LDP remote-peer
        if "ldp remote-peer" in lower:
            peer_m = re.match(r"mpls\s+ldp\s+remote-peer\s+(\S+)", header, re.IGNORECASE)
            if peer_m:
                peer_name = peer_m.group(1)
                peer_entry = {"name": peer_name, "remote_ip": None, "raw_lines": block.get("lines", [])}
                for line in block.get("lines", [])[1:]:
                    stripped = line.strip()
                    if stripped.startswith("remote-ip"):
                        peer_entry["remote_ip"] = stripped[len("remote-ip"):].strip()
                result["mpls_ldp"]["remote_peers"].append(peer_entry)
                result["mpls_ldp"]["raw_lines"].append(block.get("raw", ""))
            return

        # MPLS LDP global
        if lower.startswith("mpls ldp"):
            result["mpls_ldp"]["enabled"] = True
            result["mpls_ldp"]["raw_lines"].append(block.get("raw", ""))
            for line in block.get("lines", [])[1:]:
                stripped = line.strip()
                if "graceful-restart" in stripped.lower():
                    result["mpls_ldp"]["graceful_restart"] = True
            return

        # MPLS global — header is just "mpls" or "mpls lsr-id X.X.X.X"
        result["mpls"]["enabled"] = True
        result["mpls"]["raw_lines"].append(block.get("raw", ""))

        # Check header for lsr-id
        lsr_m = re.search(r"mpls\s+lsr-id\s+(\S+)", header, re.IGNORECASE)
        if lsr_m:
            result["mpls"]["lsr_id"] = lsr_m.group(1)

        for line in block.get("lines", [])[1:]:
            stripped = line.strip()
            sl = stripped.lower()
            if sl.startswith("mpls te"):
                result["mpls"]["te_enabled"] = True
            # lsr-id might also be inside the block
            lsr_m2 = re.search(r"lsr-id\s+(\S+)", stripped, re.IGNORECASE)
            if lsr_m2:
                result["mpls"]["lsr_id"] = lsr_m2.group(1)

    def _enrich_interfaces_core(self, result: dict) -> None:
        """Post-process interfaces to extract ISIS and MPLS/LDP sub-commands."""
        isis_process_ids = {p["process_id"] for p in result.get("isis", [])}
        for iface in result.get("interfaces", []):
            raw = iface.get("raw", "")
            for line in raw.splitlines():
                stripped = line.strip()
                sl = stripped.lower()

                # ISIS per-interface
                if sl.startswith("isis enable"):
                    rest = stripped[len("isis enable"):].strip()
                    if rest:
                        iface["isis_enabled"] = True
                        iface["isis_process_id"] = rest
                elif sl.startswith("isis circuit-type"):
                    iface["isis_circuit_type"] = stripped[len("isis circuit-type"):].strip()
                elif sl.startswith("isis cost"):
                    cost_val = stripped[len("isis cost"):].strip()
                    if cost_val and cost_val.split()[0].isdigit():
                        iface["isis_cost"] = int(cost_val.split()[0])
                elif sl.startswith("isis authentication-mode"):
                    auth_mode = stripped[len("isis authentication-mode"):].strip()
                    auth_entry = {"enabled": True, "mode": None, "has_secret": False, "secret_type": None}
                    if auth_mode:
                        parts = auth_mode.split()
                        auth_entry["mode"] = parts[0]
                        for p in parts:
                            if p in ("md5", "simple", "hmac-sha256"):
                                auth_entry["mode"] = p
                            if p in ("cipher", "simple"):
                                auth_entry["has_secret"] = True
                                auth_entry["secret_type"] = p
                    iface["isis_authentication"] = auth_entry

                # MPLS per-interface
                if sl == "mpls":
                    iface["mpls_enabled"] = True
                elif sl.startswith("mpls mtu"):
                    mtu_val = stripped[len("mpls mtu"):].strip()
                    if mtu_val.isdigit():
                        iface["mpls_mtu"] = int(mtu_val)
                elif sl == "mpls ldp":
                    iface["mpls_ldp_enabled"] = True

    def _extract_interface_nat(self, result: dict) -> None:
        """Extract NAT rules from interfaces into the global nat dict."""
        for iface in result.get("interfaces", []):
            for raw_line in iface.get("nat_outbound", []):
                m = re.match(
                    r"^nat\s+outbound\s+(?:acl\s+)?(\S+)"
                    r"(?:\s+address-group\s+(\S+))?(?:\s+no-pat)?",
                    raw_line, re.IGNORECASE
                )
                if m:
                    result["nat"]["outbound_rules"].append({
                        "acl": m.group(1),
                        "address_group": m.group(2),
                        "no_pat": "no-pat" in raw_line.lower(),
                        "vpn_instance": iface.get("vpn_instance"),
                        "raw": raw_line,
                    })
                # Note: 'interface' context is lost here; utils need to re-match
            for raw_line in iface.get("nat_server", []):
                sv_m = re.match(
                    r"^nat\s+server\s+(?:protocol\s+(\S+)\s+)?"
                    r"global\s+(\S+)(?:\s+(\S+))?\s+inside\s+(\S+)(?:\s+(\S+))?",
                    raw_line, re.IGNORECASE
                )
                if sv_m:
                    result["nat"]["server_rules"].append({
                        "protocol": sv_m.group(1),
                        "global_ip": sv_m.group(2),
                        "global_port": sv_m.group(3),
                        "inside_ip": sv_m.group(4),
                        "inside_port": sv_m.group(5),
                        "raw": raw_line,
                    })

    def _merge_interfaces_by_name(self, result: dict) -> None:
        """Merge duplicate interfaces with the same name.

        If the same interface name appears in multiple parsed blocks,
        merge fields safely without data loss.
        """
        ifaces = result.get("interfaces", [])
        merged: dict[str, dict] = {}
        merge_order: list[str] = []
        for iface in ifaces:
            name = iface.get("name", "")
            if name not in merged:
                merged[name] = dict(iface)
                merge_order.append(name)
            else:
                existing = merged[name]
                # Merge all fields from new iface into existing
                for key, value in iface.items():
                    if key == "name":
                        continue
                    existing_val = existing.get(key)
                    if value is None:
                        continue
                    if existing_val is None or existing_val == "" or existing_val == [] or existing_val == {}:
                        existing[key] = value
                        continue
                    # Lists: extend without duplicates
                    if isinstance(value, list) and isinstance(existing_val, list):
                        for item in value:
                            if item not in existing_val:
                                existing_val.append(item)
                        continue
                    # Dicts: deep merge
                    if isinstance(value, dict) and isinstance(existing_val, dict):
                        for k, v in value.items():
                            if v is not None:
                                existing_val[k] = v
                        continue
                    # Booleans: True wins
                    if isinstance(value, bool) and isinstance(existing_val, bool):
                        existing[key] = existing_val or value
                        continue
                    # Scalars: keep first non-empty
                    if value and not existing_val:
                        existing[key] = value
                    # Keep existing_val if already set
                # Merge raw text
                iface_raw = iface.get("raw", "")
                existing_raw = existing.get("raw", "")
                if iface_raw and iface_raw not in existing_raw:
                    existing["raw"] = existing_raw + "\n" + iface_raw
        result["interfaces"] = [merged[name] for name in merge_order]

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
        """Extract structured data from a BGP block, including IPv6 unicast, VPNv6, and IPv6 vpn-instance."""
        header = block["header"]
        as_number = header[len("bgp "):].strip()

        parsed = {
            "as_number": as_number,
            "peers": [],
            "networks": [],
            "has_ipv4_family": False,
            "vpnv4": {
                "peers": [],
            },
            "vpn_instances": [],
            # IPv6 sections
            "ipv6_unicast": {
                "peers": [],
                "networks": [],
            },
            "vpnv6": {
                "peers": [],
            },
            "vpn_instances_ipv6": [],
            "raw": block["raw"],
        }

        peers_by_ip: dict[str, dict] = {}
        in_ipv4_family = False
        in_vpnv4_family = False
        in_ipv6_family = False
        in_vpnv6_family = False
        current_vpn_instance = None
        current_vpn_instance_ipv6 = None

        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue

            # Family section tracking
            if stripped.startswith("ipv4-family vpnv4"):
                in_ipv4_family = False
                in_vpnv4_family = True
                in_ipv6_family = False
                in_vpnv6_family = False
                current_vpn_instance = None
                current_vpn_instance_ipv6 = None
                continue

            if stripped.startswith("ipv4-family vpn-instance "):
                in_ipv4_family = False
                in_vpnv4_family = False
                in_ipv6_family = False
                in_vpnv6_family = False
                current_vpn_instance_ipv6 = None
                vpn_name = stripped[len("ipv4-family vpn-instance "):].strip()
                current_vpn_instance = {
                    "name": vpn_name,
                    "import_routes": [],
                    "networks": [],
                    "peers": [],
                }
                parsed["vpn_instances"].append(current_vpn_instance)
                continue

            if stripped.startswith("ipv6-family vpn-instance "):
                in_ipv4_family = False
                in_vpnv4_family = False
                in_ipv6_family = False
                in_vpnv6_family = False
                current_vpn_instance = None
                vpn_name = stripped[len("ipv6-family vpn-instance "):].strip()
                current_vpn_instance_ipv6 = {
                    "name": vpn_name,
                    "import_routes": [],
                    "networks": [],
                    "peers": [],
                }
                parsed["vpn_instances_ipv6"].append(current_vpn_instance_ipv6)
                continue

            if stripped.startswith("ipv6-family vpnv6"):
                in_ipv4_family = False
                in_vpnv4_family = False
                in_ipv6_family = False
                in_vpnv6_family = True
                current_vpn_instance = None
                current_vpn_instance_ipv6 = None
                continue

            if stripped.startswith("ipv6-family unicast"):
                in_ipv4_family = False
                in_vpnv4_family = False
                in_ipv6_family = True
                in_vpnv6_family = False
                current_vpn_instance = None
                current_vpn_instance_ipv6 = None
                continue

            if stripped.startswith("ipv4-family"):
                in_ipv4_family = True
                in_vpnv4_family = False
                in_ipv6_family = False
                in_vpnv6_family = False
                current_vpn_instance = None
                current_vpn_instance_ipv6 = None
                parsed["has_ipv4_family"] = True
                continue

            # Global peer definition
            peer_match = re.match(
                r"^peer\s+(\S+)\s+as-number\s+(\d+)", stripped
            )
            vpn_context = current_vpn_instance is None and current_vpn_instance_ipv6 is None
            if peer_match and not in_vpnv4_family and not in_vpnv6_family and vpn_context:
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

            # Peer inside vpn-instance (IPv4)
            if peer_match and current_vpn_instance is not None:
                peer_ip = peer_match.group(1)
                peer = {
                    "ip": peer_ip,
                    "remote_as": peer_match.group(2),
                    "route_policy_import": None,
                    "route_policy_export": None,
                }
                current_vpn_instance["peers"].append(peer)
                continue

            # Peer inside vpn-instance IPv6
            if peer_match and current_vpn_instance_ipv6 is not None:
                peer_ip = peer_match.group(1)
                peer = {
                    "ip": peer_ip,
                    "remote_as": peer_match.group(2),
                    "route_policy_import": None,
                    "route_policy_export": None,
                }
                current_vpn_instance_ipv6["peers"].append(peer)
                continue

            # Network
            net = self._parse_bgp_network(stripped)
            if net and in_ipv6_family:
                # Parse IPv6 network with prefix length
                v6net = self._parse_bgp_ipv6_network(stripped)
                if v6net:
                    parsed["ipv6_unicast"]["networks"].append(v6net)
                else:
                    parsed["ipv6_unicast"]["networks"].append(net)
                continue
            if net and current_vpn_instance_ipv6 is not None:
                v6net = self._parse_bgp_ipv6_network(stripped)
                if v6net:
                    current_vpn_instance_ipv6["networks"].append(v6net)
                else:
                    current_vpn_instance_ipv6["networks"].append(net)
                continue
            if net and current_vpn_instance is None:
                parsed["networks"].append(net)
                continue
            if net and current_vpn_instance is not None:
                current_vpn_instance["networks"].append(net)
                continue

            # import-route inside vpn-instance
            ir_match = re.match(r"^import-route\s+(\S+)", stripped)
            if ir_match and current_vpn_instance is not None:
                current_vpn_instance["import_routes"].append(ir_match.group(1))
                continue
            if ir_match and current_vpn_instance_ipv6 is not None:
                current_vpn_instance_ipv6["import_routes"].append(ir_match.group(1))
                continue

            # Peer sub-commands
            if stripped.startswith("peer "):
                if current_vpn_instance is not None:
                    self._parse_bgp_vpn_peer_line(stripped, current_vpn_instance["peers"])
                elif current_vpn_instance_ipv6 is not None:
                    self._parse_bgp_vpn_peer_line(stripped, current_vpn_instance_ipv6["peers"])
                elif in_vpnv6_family:
                    self._parse_bgp_vpnv6_peer_line(stripped, parsed["vpnv6"]["peers"])
                elif in_vpnv4_family:
                    self._parse_bgp_vpnv4_peer_line(stripped, parsed["vpnv4"]["peers"])
                elif in_ipv6_family:
                    self._parse_bgp_ipv6_peer_line(stripped, parsed["ipv6_unicast"]["peers"])
                else:
                    self._parse_bgp_peer_line(stripped, peers_by_ip, in_ipv4_family)
                continue

        return parsed
        return parsed

    def _parse_bgp_vpnv4_peer_line(
        self, stripped: str, vpnv4_peers: list[dict]
    ) -> None:
        """Parse a VPNv4 peer sub-command."""
        ip_match = re.match(r"^peer\s+(\S+)", stripped)
        if not ip_match:
            return
        peer_ip = ip_match.group(1)

        rest = stripped[len(f"peer {peer_ip}"):].strip()
        if rest == "enable":
            # Add or update peer
            for p in vpnv4_peers:
                if p["peer"] == peer_ip:
                    p["enabled"] = True
                    return
            vpnv4_peers.append({
                "peer": peer_ip,
                "enabled": True,
                "route_policy_import": None,
                "route_policy_export": None,
            })
            return

        # Check if peer already exists or create new entry
        peer_entry = None
        for p in vpnv4_peers:
            if p["peer"] == peer_ip:
                peer_entry = p
                break
        if peer_entry is None:
            peer_entry = {
                "peer": peer_ip,
                "enabled": False,
                "route_policy_import": None,
                "route_policy_export": None,
            }
            vpnv4_peers.append(peer_entry)

        # route-policy import/export
        rp_match = re.match(r"^route-policy\s+(\S+)\s+(import|export)", rest)
        if rp_match:
            policy_name = rp_match.group(1)
            direction = rp_match.group(2)
            if direction == "import":
                peer_entry["route_policy_import"] = policy_name
            else:
                peer_entry["route_policy_export"] = policy_name

    def _parse_bgp_vpnv6_peer_line(
        self, stripped: str, vpnv6_peers: list[dict]
    ) -> None:
        """Parse a VPNv6 peer sub-command."""
        ip_match = re.match(r"^peer\s+(\S+)", stripped)
        if not ip_match:
            return
        peer_ip = ip_match.group(1)
        rest = stripped[len(f"peer {peer_ip}"):].strip()
        if rest == "enable":
            for p in vpnv6_peers:
                if p["peer"] == peer_ip:
                    p["enabled"] = True
                    return
            vpnv6_peers.append({
                "peer": peer_ip,
                "enabled": True,
                "route_policy_import": None,
                "route_policy_export": None,
            })
            return
        peer_entry = None
        for p in vpnv6_peers:
            if p["peer"] == peer_ip:
                peer_entry = p
                break
        if peer_entry is None:
            peer_entry = {
                "peer": peer_ip,
                "enabled": False,
                "route_policy_import": None,
                "route_policy_export": None,
            }
            vpnv6_peers.append(peer_entry)
        rp_match = re.match(r"^route-policy\s+(\S+)\s+(import|export)", rest)
        if rp_match:
            policy_name = rp_match.group(1)
            direction = rp_match.group(2)
            if direction == "import":
                peer_entry["route_policy_import"] = policy_name
            else:
                peer_entry["route_policy_export"] = policy_name

    def _parse_bgp_ipv6_peer_line(
        self, stripped: str, ipv6_peers: list[dict]
    ) -> None:
        """Parse an IPv6 unicast peer sub-command."""
        ip_match = re.match(r"^peer\s+(\S+)", stripped)
        if not ip_match:
            return
        peer_ip = ip_match.group(1)
        rest = stripped[len(f"peer {peer_ip}"):].strip()
        if rest == "enable":
            for p in ipv6_peers:
                if p["peer"] == peer_ip:
                    p["enabled"] = True
                    return
            ipv6_peers.append({
                "peer": peer_ip,
                "enabled": True,
                "route_policy_import": None,
                "route_policy_export": None,
            })
            return
        peer_entry = None
        for p in ipv6_peers:
            if p["peer"] == peer_ip:
                peer_entry = p
                break
        if peer_entry is None:
            ipv6_peers.append({
                "peer": peer_ip,
                "enabled": False,
                "route_policy_import": None,
                "route_policy_export": None,
            })
            return
        rp_match = re.match(r"^route-policy\s+(\S+)\s+(import|export)", rest)
        if rp_match:
            policy_name = rp_match.group(1)
            direction = rp_match.group(2)
            if direction == "import":
                peer_entry["route_policy_import"] = policy_name
            else:
                peer_entry["route_policy_export"] = policy_name

    def _parse_bgp_vpn_peer_line(
        self, stripped: str, ce_peers: list[dict]
    ) -> None:
        """Parse a CE peer sub-command inside vpn-instance."""
        ip_match = re.match(r"^peer\s+(\S+)", stripped)
        if not ip_match:
            return
        peer_ip = ip_match.group(1)
        rest = stripped[len(f"peer {peer_ip}"):].strip()

        # route-policy import/export
        rp_match = re.match(r"^route-policy\s+(\S+)\s+(import|export)", rest)
        if rp_match:
            policy_name = rp_match.group(1)
            direction = rp_match.group(2)
            for p in ce_peers:
                if p["ip"] == peer_ip:
                    if direction == "import":
                        p["route_policy_import"] = policy_name
                    else:
                        p["route_policy_export"] = policy_name
                    return

    def _parse_bgp_network(self, stripped: str) -> str | None:
        """Extract a network advertisement from a BGP sub-command."""
        match = re.match(
            r"^network\s+(\S+(?:\.\d+(?:\.\d+)?)?(?:\s+mask\s+\S+)?)",
            stripped,
        )
        return match.group(1).strip() if match else None

    def _parse_bgp_ipv6_network(self, stripped: str) -> dict | None:
        """Parse an IPv6 BGP network with prefix length.

        Formats:
            network 2001:db8:200:: 48
            network 2001:db8:200::/48
        """
        m = re.match(r"^network\s+(\S+?)\s+(\d+)$", stripped)
        if m:
            return {"prefix": f"{m.group(1)}/{m.group(2)}", "network": m.group(1), "prefix_length": int(m.group(2)), "raw": stripped}
        m = re.match(r"^network\s+(\S+?)/(\d+)$", stripped)
        if m:
            return {"prefix": f"{m.group(1)}/{m.group(2)}", "network": m.group(1), "prefix_length": int(m.group(2)), "raw": stripped}
        return None

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

    # ── IPv6 static routes ────────────────────────────────────────────────

    def _extract_ipv6_static_routes(self, text: str) -> list:
        """Extract all ipv6 route-static lines."""
        routes = []
        for match in self.RE_IPV6_ROUTE_STATIC.finditer(text):
            route_text = match.group(1).strip()
            route = {
                "raw": f"ipv6 route-static {route_text}",
                "vpn_instance": None,
                "destination": None,
                "prefix_length": None,
                "prefix": None,
                "next_hop": None,
                "description": None,
            }
            tokens = route_text.split()
            pos = 0
            if pos < len(tokens) and tokens[pos].lower() == "vpn-instance":
                pos += 1
                if pos < len(tokens):
                    route["vpn_instance"] = tokens[pos]
                    pos += 1
            if len(tokens) > pos:
                route["destination"] = tokens[pos]
                pos += 1
            if len(tokens) > pos:
                try:
                    route["prefix_length"] = int(tokens[pos])
                    pos += 1
                except ValueError:
                    pass
            if len(tokens) > pos and tokens[pos] != "description":
                route["next_hop"] = tokens[pos]
                pos += 1
            while pos < len(tokens):
                kw = tokens[pos].lower()
                if kw == "description" and pos + 1 < len(tokens):
                    pos += 1
                    route["description"] = tokens[pos]
                pos += 1
            if route["destination"] and route["prefix_length"] is not None:
                route["prefix"] = f"{route['destination']}/{route['prefix_length']}"
            routes.append(route)
        return routes

    # ── NAT parser methods ───────────────────────────────────────────────

    RE_NAT_ADDRESS_GROUP = re.compile(
        r"^nat\s+address-group\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+vpn-instance\s+(\S+))?",
        re.IGNORECASE,
    )

    def _parse_nat_line(self, header: str, result: dict) -> None:
        """Parse a standalone NAT command line."""
        header_lower = header.lower()

        # nat address-group <name> <start> <end> [vpn-instance <name>]
        ag_m = self.RE_NAT_ADDRESS_GROUP.match(header)
        if ag_m:
            result["nat"]["address_groups"].append({
                "name": ag_m.group(1),
                "start_ip": ag_m.group(2),
                "end_ip": ag_m.group(3),
                "vpn_instance": ag_m.group(4),
                "raw": header,
            })
            return
        # nat address-group might also appear inside a block (but typically standalone)
        # Fallback: try simpler regex
        ag_simple = re.match(
            r"^nat\s+address-group\s+(\S+)\s+(\S+)\s+(\S+)",
            header, re.IGNORECASE
        )
        if ag_simple:
            result["nat"]["address_groups"].append({
                "name": ag_simple.group(1),
                "start_ip": ag_simple.group(2),
                "end_ip": ag_simple.group(3),
                "vpn_instance": None,
                "raw": header,
            })
            return

        # nat outbound <acl> [address-group <name>] [no-pat]
        ob_m = re.match(
            r"^nat\s+outbound\s+(?:acl\s+)?(\S+)"
            r"(?:\s+address-group\s+(\S+))?(?:\s+no-pat)?"
            r"(?:\s+vpn-instance\s+(\S+))?",
            header, re.IGNORECASE
        )
        if ob_m and header_lower.startswith("nat outbound"):
            result["nat"]["outbound_rules"].append({
                "acl": ob_m.group(1),
                "address_group": ob_m.group(2),
                "no_pat": "no-pat" in header_lower,
                "vpn_instance": ob_m.group(3),
                "raw": header,
            })
            return

        # nat static [protocol <proto>] global <ip> [port] inside <ip> [port] [vpn-instance <name>]
        st_m = re.match(
            r"^nat\s+static\s+(?:protocol\s+(\S+)\s+)?"
            r"global\s+(\S+)(?:\s+(\S+))?\s+inside\s+(\S+)(?:\s+(\S+))?"
            r"(?:\s+vpn-instance\s+(\S+))?",
            header, re.IGNORECASE
        )
        if st_m and header_lower.startswith("nat static"):
            result["nat"]["static_rules"].append({
                "protocol": st_m.group(1),
                "global_ip": st_m.group(2),
                "global_port": st_m.group(3),
                "inside_ip": st_m.group(4),
                "inside_port": st_m.group(5),
                "vpn_instance": st_m.group(6),
                "raw": header,
            })
            return

        # nat server [protocol <proto>] global <ip> [port] inside <ip> [port]
        sv_m = re.match(
            r"^nat\s+server\s+(?:protocol\s+(\S+)\s+)?"
            r"global\s+(\S+)(?:\s+(\S+))?\s+inside\s+(\S+)(?:\s+(\S+))?",
            header, re.IGNORECASE
        )
        if sv_m and header_lower.startswith("nat server"):
            result["nat"]["server_rules"].append({
                "protocol": sv_m.group(1),
                "global_ip": sv_m.group(2),
                "global_port": sv_m.group(3),
                "inside_ip": sv_m.group(4),
                "inside_port": sv_m.group(5),
                "raw": header,
            })
            return

        # nat alg <protocol> enable|disable
        alg_m = re.match(
            r"^nat\s+alg\s+(\S+)\s+(enable|disable)",
            header, re.IGNORECASE
        )
        if alg_m:
            result["nat"]["alg"].append({
                "protocol": alg_m.group(1),
                "enabled": alg_m.group(2).lower() == "enable",
                "raw": header,
            })
            return

    # ── QoS parser methods ──────────────────────────────────────────────

    def _parse_traffic_classifier_block(self, block: dict) -> dict | None:
        """Parse a traffic classifier block.

        VRP format:
            traffic classifier NAME operator or/and
             if-match acl <id>
             if-match any
             if-match dscp <value>
             if-match 8021p <value>
            #
        """
        header = block["header"]
        m = re.match(
            r"^traffic\s+classifier\s+(\S+)(?:\s+operator\s+(or|and))?",
            header, re.IGNORECASE
        )
        if not m:
            return None

        parsed = {
            "name": m.group(1),
            "operator": m.group(2) or "or",
            "if_match": [],
            "raw_lines": block.get("lines", []),
            "raw": block.get("raw", ""),
        }

        for line in block.get("lines", [])[1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue

            m_acl = re.match(r"^if-match\s+acl\s+(\S+)", stripped, re.IGNORECASE)
            if m_acl:
                parsed["if_match"].append({
                    "type": "acl", "value": m_acl.group(1), "raw": stripped
                })
                continue

            m_any = re.match(r"^if-match\s+any$", stripped, re.IGNORECASE)
            if m_any:
                parsed["if_match"].append({
                    "type": "any", "value": None, "raw": stripped
                })
                continue

            m_dscp = re.match(r"^if-match\s+dscp\s+(\S+)", stripped, re.IGNORECASE)
            if m_dscp:
                parsed["if_match"].append({
                    "type": "dscp", "value": m_dscp.group(1), "raw": stripped
                })
                continue

            m_8021p = re.match(r"^if-match\s+8021p\s+(\S+)", stripped, re.IGNORECASE)
            if m_8021p:
                parsed["if_match"].append({
                    "type": "8021p", "value": m_8021p.group(1), "raw": stripped
                })
                continue

            # Preserve unknown if-match lines
            if stripped.startswith("if-match "):
                parsed["if_match"].append({
                    "type": "unknown", "value": stripped[len("if-match "):], "raw": stripped
                })

        return parsed

    def _parse_traffic_behavior_block(self, block: dict) -> dict | None:
        """Parse a traffic behavior block.

        VRP format:
            traffic behavior NAME
             car cir <rate> pir <rate> [cbs <size>] [pbs <size>]
                 [green <action>] [yellow <action>] [red <action>]
             statistic enable
             remark dscp <value>
             queue <type> bandwidth pct <pct>
            #
        """
        header = block["header"]
        m = re.match(r"^traffic\s+behavior\s+(\S+)", header, re.IGNORECASE)
        if not m:
            return None

        parsed = {
            "name": m.group(1),
            "car": None,
            "statistics_enabled": False,
            "actions": [],
            "raw_lines": block.get("lines", []),
            "raw": block.get("raw", ""),
        }

        for line in block.get("lines", [])[1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue

            # CAR (Committed Access Rate)
            car_m = re.match(
                r"^car\s+cir\s+(\d+)(.*)",
                stripped, re.IGNORECASE
            )
            if car_m:
                car_data = {"cir": int(car_m.group(1))}
                rest = car_m.group(2)
                pir_m = re.search(r"pir\s+(\d+)", rest, re.IGNORECASE)
                if pir_m:
                    car_data["pir"] = int(pir_m.group(1))
                cbs_m = re.search(r"cbs\s+(\d+)", rest, re.IGNORECASE)
                if cbs_m:
                    car_data["cbs"] = int(cbs_m.group(1))
                pbs_m = re.search(r"pbs\s+(\d+)", rest, re.IGNORECASE)
                if pbs_m:
                    car_data["pbs"] = int(pbs_m.group(1))
                for color in ("green", "yellow", "red"):
                    cm = re.search(rf"{color}\s+(\S+)", rest, re.IGNORECASE)
                    if cm:
                        car_data[f"{color}_action"] = cm.group(1)
                parsed["car"] = car_data
                parsed["actions"].append({"type": "car", "raw": stripped})
                continue

            # statistic enable
            if re.match(r"^statistic\s+enable$", stripped, re.IGNORECASE):
                parsed["statistics_enabled"] = True
                parsed["actions"].append({"type": "statistic_enable", "raw": stripped})
                continue

            # remark dscp
            rd_m = re.match(r"^remark\s+dscp\s+(\S+)", stripped, re.IGNORECASE)
            if rd_m:
                parsed["actions"].append({
                    "type": "remark_dscp", "value": rd_m.group(1), "raw": stripped
                })
                continue

            # queue
            q_m = re.match(r"^queue\s+(\S+)", stripped, re.IGNORECASE)
            if q_m:
                parsed["actions"].append({
                    "type": "queue", "value": q_m.group(1),
                    "details": stripped[len(f"queue {q_m.group(1)}"):].strip(),
                    "raw": stripped,
                })
                continue

            # Unknown actions - preserve raw
            parsed["actions"].append({"type": "unknown", "raw": stripped})

        return parsed

    def _parse_traffic_policy_block(self, block: dict) -> dict | None:
        """Parse a traffic policy block.

        VRP format:
            traffic policy NAME
             classifier NAME behavior NAME precedence <N>
            #
        """
        header = block["header"]
        m = re.match(r"^traffic\s+policy\s+(\S+)", header, re.IGNORECASE)
        if not m:
            return None

        parsed = {
            "name": m.group(1),
            "classifiers": [],
            "raw_lines": block.get("lines", []),
            "raw": block.get("raw", ""),
        }

        for line in block.get("lines", [])[1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue

            cm = re.match(
                r"^classifier\s+(\S+)\s+behavior\s+(\S+)(?:\s+precedence\s+(\d+))?",
                stripped, re.IGNORECASE
            )
            if cm:
                entry = {
                    "classifier": cm.group(1),
                    "behavior": cm.group(2),
                }
                if cm.group(3):
                    entry["precedence"] = int(cm.group(3))
                parsed["classifiers"].append(entry)

        return parsed

    def _parse_qos_profile_block(self, block: dict) -> dict | None:
        """Parse a qos-profile block.

        VRP format:
            qos-profile NAME
             car cir <rate> pir <rate>
            #
        """
        header = block["header"]
        m = re.match(r"^qos-profile\s+(\S+)", header, re.IGNORECASE)
        if not m:
            return None

        parsed = {
            "name": m.group(1),
            "car": None,
            "raw_lines": block.get("lines", []),
            "raw": block.get("raw", ""),
        }

        for line in block.get("lines", [])[1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue

            car_m = re.match(
                r"^car\s+cir\s+(\d+)(.*)", stripped, re.IGNORECASE
            )
            if car_m:
                car_data = {"cir": int(car_m.group(1))}
                rest = car_m.group(2)
                pir_m = re.search(r"pir\s+(\d+)", rest, re.IGNORECASE)
                if pir_m:
                    car_data["pir"] = int(pir_m.group(1))
                parsed["car"] = car_data

        return parsed

    def _parse_vpn_instance_block(self, block: dict) -> dict | None:
        """Extract structured data from a VPN-instance block.

        VRP format:
            ip vpn-instance CLIENTE-A
             description Cliente A - L3VPN
             ipv4-family
              route-distinguisher 65000:100
              vpn-target 65000:100 export-extcommunity
              vpn-target 65000:100 import-extcommunity
            #

        Returns:
            dict with keys: name, description, address_families, vpn_targets, raw_lines
            or None if parsing fails.
        """
        header = block["header"]
        m = re.match(r"ip vpn-instance\s+(\S+)", header, re.IGNORECASE)
        if not m:
            return None

        name = m.group(1)
        parsed = {
            "name": name,
            "description": None,
            "address_families": {},
            "raw_lines": block.get("lines", []),
            "raw": block.get("raw", ""),
        }

        current_af = None
        for line in block.get("lines", [])[1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue

            # Description (before any ipv4-family block)
            if stripped.lower().startswith("description ") and current_af is None:
                parsed["description"] = stripped[len("description "):].strip().strip('"')
                continue

            # Address family
            af_match = re.match(r"^(\S+-family)\s*$", stripped, re.IGNORECASE)
            if af_match:
                current_af = af_match.group(1).lower().replace("-family", "")
                if current_af not in parsed["address_families"]:
                    parsed["address_families"][current_af] = {
                        "route_distinguisher": None,
                        "vpn_targets": [],
                    }
                continue

            # route-distinguisher
            rd_match = re.match(r"^route-distinguisher\s+(\S+)", stripped, re.IGNORECASE)
            if rd_match and current_af:
                parsed["address_families"][current_af]["route_distinguisher"] = rd_match.group(1)
                continue

            # vpn-target
            vt_match = re.match(
                r"^vpn-target\s+(\S+)\s+(export-extcommunity|import-extcommunity|both)",
                stripped,
                re.IGNORECASE,
            )
            if vt_match and current_af:
                value = vt_match.group(1)
                direction = vt_match.group(2).lower()
                if direction == "both":
                    parsed["address_families"][current_af]["vpn_targets"].append(
                        {"value": value, "direction": "export"}
                    )
                    parsed["address_families"][current_af]["vpn_targets"].append(
                        {"value": value, "direction": "import"}
                    )
                else:
                    dir_clean = direction.replace("-extcommunity", "")
                    parsed["address_families"][current_af]["vpn_targets"].append(
                        {"value": value, "direction": dir_clean}
                    )
                continue

            # Description inside an address-family section
            if stripped.lower().startswith("description ") and current_af:
                if not parsed["description"]:
                    parsed["description"] = stripped[len("description "):].strip().strip('"')
                continue

        return parsed

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
        """Parse an AAA configuration block with structured schemes and domains."""
        parsed = {
            "type": "aaa",
            "authentication_schemes": [],
            "accounting_schemes": [],
            "authorization_schemes": [],
            "domains": [],
            "raw": block["raw"],
        }
        current_section = None
        current_item = None
        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                current_section = None
                current_item = None
                continue
            if stripped.startswith("authentication-scheme ") and current_section != "domain":
                current_section = "auth"
                current_item = {"name": stripped[len("authentication-scheme "):].strip(), "authentication_mode": [], "raw_lines": []}
                parsed["authentication_schemes"].append(current_item)
            elif stripped.startswith("authorization-scheme ") and current_section != "domain":
                current_section = "author"
                current_item = {"name": stripped[len("authorization-scheme "):].strip(), "authorization_mode": [], "raw_lines": []}
                parsed["authorization_schemes"].append(current_item)
            elif stripped.startswith("accounting-scheme ") and current_section != "domain":
                current_section = "acct"
                current_item = {"name": stripped[len("accounting-scheme "):].strip(), "accounting_mode": [], "accounting_realtime": None, "raw_lines": []}
                parsed["accounting_schemes"].append(current_item)
            elif stripped.startswith("domain "):
                current_section = "domain"
                current_item = {"name": stripped[len("domain "):].strip(), "authentication_scheme": None, "accounting_scheme": None, "authorization_scheme": None, "radius_server_group": None, "ip_pool": None, "dns_primary": None, "dns_secondary": None, "raw_lines": []}
                parsed["domains"].append(current_item)
            elif current_item is not None:
                current_item.setdefault("raw_lines", []).append(stripped)
                if current_section == "auth" and stripped.startswith("authentication-mode "):
                    current_item["authentication_mode"] = stripped[len("authentication-mode "):].strip().split()
                elif current_section == "author" and stripped.startswith("authorization-mode "):
                    current_item["authorization_mode"] = stripped[len("authorization-mode "):].strip().split()
                elif current_section == "acct":
                    if stripped.startswith("accounting-mode "):
                        current_item["accounting_mode"] = stripped[len("accounting-mode "):].strip().split()
                    rt = re.match(r"^accounting\s+realtime\s+(\d+)", stripped, re.I)
                    if rt:
                        current_item["accounting_realtime"] = int(rt.group(1))
                elif current_section == "domain":
                    m = re.match(r"^authentication-scheme\s+(\S+)", stripped)
                    if m: current_item["authentication_scheme"] = m.group(1)
                    m = re.match(r"^accounting-scheme\s+(\S+)", stripped)
                    if m: current_item["accounting_scheme"] = m.group(1)
                    m = re.match(r"^authorization-scheme\s+(\S+)", stripped)
                    if m: current_item["authorization_scheme"] = m.group(1)
                    m = re.match(r"^radius-server\s+group\s+(\S+)", stripped)
                    if m: current_item["radius_server_group"] = m.group(1)
                    m = re.match(r"^ip-pool\s+(\S+)", stripped)
                    if m: current_item["ip_pool"] = m.group(1)
                    m = re.match(r"^dns\s+(?:primary-ip\s+)?(\S+)", stripped)
                    if m:
                        val = stripped.split()[-1]  # Last word is the IP
                        if not current_item["dns_primary"]:
                            current_item["dns_primary"] = val
                        elif not current_item["dns_secondary"]:
                            current_item["dns_secondary"] = val
        return parsed

    def _parse_radius_block(self, block: dict) -> dict:
        """Parse a RADIUS server configuration block (group or template)."""
        header = block["header"]
        parts = header.replace("radius-server", "").replace("radius server", "").strip()
        tokens = parts.split()
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
            "has_authentication": False,
            "has_accounting": False,
            "authentication_servers": [],
            "accounting_servers": [],
            "has_shared_key": False,
            "shared_key_encrypted": True,
            "shared_key_type": None,
            "retransmit": None,
            "timeout": None,
            "raw": block["raw"],
        }
        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue
            am = re.match(r"radius-server\s+authentication\s+(\S+)\s+(\d+)(.*)", stripped, re.I)
            if am:
                parsed["has_authentication"] = True
                server = {"ip": am.group(1), "port": int(am.group(2))}
                rest2 = am.group(3)
                wm = re.search(r"weight\s+(\d+)", rest2, re.I)
                if wm:
                    server["weight"] = int(wm.group(1))
                parsed["authentication_servers"].append(server)
                continue
            acm = re.match(r"radius-server\s+accounting\s+(\S+)\s+(\d+)(.*)", stripped, re.I)
            if acm:
                parsed["has_accounting"] = True
                server = {"ip": acm.group(1), "port": int(acm.group(2))}
                rest2 = acm.group(3)
                wm = re.search(r"weight\s+(\d+)", rest2, re.I)
                if wm:
                    server["weight"] = int(wm.group(1))
                parsed["accounting_servers"].append(server)
                continue
            sk = re.match(r"radius-server\s+shared-key\s+(cipher|simple)\s+", stripped, re.I)
            if sk:
                parsed["has_shared_key"] = True
                parsed["shared_key_type"] = sk.group(1)
                parsed["shared_key_encrypted"] = sk.group(1) == "cipher"
                continue
            sk2 = re.match(r"radius-server\s+shared-key\s+", stripped, re.I)
            if sk2:
                parsed["has_shared_key"] = True
                parsed["shared_key_type"] = "unknown"
                parsed["shared_key_encrypted"] = False
                continue
            rt = re.match(r"radius-server\s+retransmit\s+(\d+)", stripped, re.I)
            if rt:
                parsed["retransmit"] = int(rt.group(1))
                continue
            to = re.match(r"radius-server\s+timeout\s+(\d+)", stripped, re.I)
            if to:
                parsed["timeout"] = int(to.group(1))
                continue
        return parsed

    def _parse_ip_pool_block(self, block: dict) -> dict:
        """Parse an IP pool configuration block (local or remote)."""
        header = block["header"]
        rest = header[len("ip pool "):].strip() if header.startswith("ip pool") else ""
        parts = rest.split()
        pool_name = parts[0] if parts else ""
        parsed = {
            "name": pool_name,
            "type": parts[1] if len(parts) > 1 else None,
            "mode": parts[2] if len(parts) > 2 else None,
            "gateway": None,
            "mask": None,
            "sections": [],
            "dns_servers": [],
            "lease": None,
            "radius_server_group": None,
            "raw": block["raw"],
        }
        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue
            if stripped.startswith("gateway "):
                gw = stripped[len("gateway "):].strip()
                gw_parts = gw.split()
                parsed["gateway"] = gw_parts[0]
                if len(gw_parts) > 1:
                    parsed["mask"] = gw_parts[1]
            elif stripped.startswith("dns-server "):
                dns_part = stripped[len("dns-server "):].strip()
                for dns_ip in dns_part.split():
                    if dns_ip not in parsed["dns_servers"]:
                        parsed["dns_servers"].append(dns_ip)
            elif stripped.startswith("section "):
                sec = re.match(r"section\s+(\S+)\s+(\S+)\s+(\S+)", stripped)
                if sec:
                    parsed["sections"].append({"id": sec.group(1), "start_ip": sec.group(2), "end_ip": sec.group(3)})
            elif stripped.startswith("lease "):
                parsed["lease"] = stripped[len("lease "):].strip()
            elif stripped.startswith("radius-server group "):
                parsed["radius_server_group"] = stripped[len("radius-server group "):].strip()
        return parsed

    def _parse_aaa_domain_block(self, block: dict) -> dict:
        """Parse an AAA domain configuration block (standalone, outside AAA)."""
        header = block["header"]
        domain_name = header[len("domain "):].strip() if header.startswith("domain ") else ""
        parsed = {
            "name": domain_name,
            "type": "aaa_domain",
            "authentication_scheme": None,
            "accounting_scheme": None,
            "authorization_scheme": None,
            "radius_server_group": None,
            "ip_pool": None,
            "dns_primary": None,
            "dns_secondary": None,
            "raw": block["raw"],
        }
        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue
            if stripped.startswith("authentication-scheme "):
                parsed["authentication_scheme"] = stripped.split()[-1]
            elif stripped.startswith("accounting-scheme "):
                parsed["accounting_scheme"] = stripped.split()[-1]
            elif stripped.startswith("authorization-scheme "):
                parsed["authorization_scheme"] = stripped.split()[-1]
            elif stripped.startswith("radius-server "):
                parsed["radius_server_group"] = stripped.split()[-1]
            elif stripped.startswith("ip-pool "):
                parsed["ip_pool"] = stripped.split()[-1]
            elif stripped.startswith("dns "):
                dns_val = stripped.split()[-1]  # Last word is the IP
                if not parsed["dns_primary"]:
                    parsed["dns_primary"] = dns_val
                elif not parsed["dns_secondary"]:
                    parsed["dns_secondary"] = dns_val
        return parsed

    def _parse_bas_block(self, block: dict) -> dict:
        """Parse a BAS configuration block."""
        parsed = {
            "type": "bas",
            "access_type": None,
            "default_domain": None,
            "pre_authentication_domain": None,
            "authentication_method": None,
            "accounting_copy_radius_group": None,
            "ip_trigger": False,
            "arp_trigger": False,
            "ipv6_trigger": False,
            "raw": block["raw"],
        }
        for line in block["lines"][1:]:
            stripped = line.strip()
            if not stripped or stripped == "#":
                continue
            if stripped.startswith("access-type "):
                # Extract just the access type, ignore default-domain etc.
                at = stripped[len("access-type "):].strip()
                at_parts = at.split()
                parsed["access_type"] = at_parts[0] if at_parts else at
                # Also check for default-domain on the same line
                dd = re.match(r"default-domain\s+authentication\s+(\S+)", stripped, re.I)
                if dd:
                    parsed["default_domain"] = dd.group(1)
                pd = re.match(r"default-domain\s+pre-authentication\s+(\S+)", stripped, re.I)
                if pd:
                    parsed["pre_authentication_domain"] = pd.group(1)
            elif stripped.startswith("authentication-method "):
                parsed["authentication_method"] = stripped[len("authentication-method "):].strip()
            elif stripped.startswith("accounting-copy"):
                ac = re.match(r"accounting-copy\s+radius-server\s+group\s+(\S+)", stripped, re.I)
                if ac:
                    parsed["accounting_copy_radius_group"] = ac.group(1)
            elif stripped == "ip-trigger":
                parsed["ip_trigger"] = True
            elif stripped == "arp-trigger":
                parsed["arp_trigger"] = True
            elif stripped == "ipv6-trigger":
                parsed["ipv6_trigger"] = True
            else:
                dd = re.match(r"default-domain\s+authentication\s+(\S+)", stripped, re.I)
                if dd:
                    parsed["default_domain"] = dd.group(1)
                pd = re.match(r"default-domain\s+pre-authentication\s+(\S+)", stripped, re.I)
                if pd:
                    parsed["pre_authentication_domain"] = pd.group(1)
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

        # Extract name from header: "ip ip-prefix NAME ..." or "ip ipv6-prefix NAME ..."
        m = re.match(r"ip\s+(?:prefix-list|ip-prefix|ipv6-prefix)\s+(\S+)", header, re.IGNORECASE)
        if not m:
            return None
        name = m.group(1)

        rules = []
        is_ipv6 = "ipv6" in header.lower()
        for line in full_lines:
            stripped = line.strip()
            # Each line is self-contained: "ip ip-prefix NAME index N permit|deny PREFIX MASK [ge|le]"
            rule_match = re.match(
                r"(?:ip\s+(?:prefix-list|ip-prefix|ipv6-prefix)\s+\S+\s+)?"
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
            "is_ipv6": is_ipv6,
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
            im = re.match(r"if-match\s+ipv6\s+prefix-list\s+(\S+)", stripped, re.IGNORECASE)
            if im:
                if_matches.append({"type": "ipv6-prefix-list", "name": im.group(1), "raw": stripped})
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
