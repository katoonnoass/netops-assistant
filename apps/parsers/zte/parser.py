"""ZTE OLT configuration parser.

Initial target: ZXA10 C300/C320/C600 style OLT configurations.
"""

from __future__ import annotations

import ipaddress
import re

from apps.parsers.base import BaseParser


class ZTEOLTParser(BaseParser):
    vendor = "zte"

    RE_HOSTNAME = re.compile(r"^(?:hostname|sysname)\s+(.+)$", re.IGNORECASE)
    RE_INTERFACE = re.compile(r"^interface\s+(.+)$", re.IGNORECASE)
    RE_PON = re.compile(r"gpon-olt_([0-9/]+)", re.IGNORECASE)
    RE_ONU = re.compile(r"gpon-onu_([0-9/]+):(\d+)", re.IGNORECASE)
    RE_ONU_DECL = re.compile(r"^onu\s+(\d+)\s+type\s+(\S+)\s+sn\s+(\S+)", re.IGNORECASE)
    RE_ONU_NAME = re.compile(r"^onu\s+(\d+)\s+name\s+(.+)$", re.IGNORECASE)
    RE_VLAN = re.compile(r"^vlan\s+(\d+)", re.IGNORECASE)
    RE_BGP = re.compile(r"^(?:bgp|router bgp)\s+(\d+)", re.IGNORECASE)
    RE_OSPF = re.compile(r"^(?:ospf|router ospf)\s+(\d+)", re.IGNORECASE)

    BLOCK_STARTERS = (
        "interface",
        "pon-onu-mng",
        "vlan",
        "bgp",
        "router bgp",
        "ospf",
        "router ospf",
        "profile",
        "onu-type",
        "ip access-list",
        "acl",
    )

    def parse(self) -> dict:
        text = self.raw_config or ""
        result: dict = {
            "vendor": "zte",
            "platform": "zte_olt",
            "sysname": "",
            "hostname": "",
            "blocks": [],
            "interfaces": [],
            "static_routes": [],
            "bgp": [],
            "ospf": [],
            "vlans": [],
            "zte_olt": {
                "enabled": False,
                "pon_ports": [],
                "onus": [],
                "service_ports": [],
                "profiles": {
                    "onu_types": [],
                    "tcont_profiles": [],
                    "line_profiles": [],
                    "service_profiles": [],
                    "raw_profiles": [],
                },
                "vlans": [],
            },
            "routing": {"bgp": False, "ospf": False, "static_routes": False},
            "raw": text,
            "block_count": 0,
            "raw_summary": {},
        }
        if not text.strip():
            return result

        result["hostname"] = self._extract_hostname(text)
        result["sysname"] = result["hostname"]
        blocks = self._split_blocks(text)
        result["blocks"] = blocks
        result["block_count"] = len(blocks)

        onu_index: dict[str, dict] = {}
        pon_index: dict[str, dict] = {}

        for block in blocks:
            block_type = block["type"]
            if block_type == "interface":
                interface = self._parse_interface_block(block)
                result["interfaces"].append(interface)
                self._parse_olt_interface(block, interface, result["zte_olt"], pon_index, onu_index)
            elif block_type == "pon_onu_mng":
                self._parse_pon_onu_mng_block(block, result["zte_olt"], onu_index)
            elif block_type == "vlan":
                vlan = self._parse_vlan_block(block)
                result["vlans"].append(vlan)
                result["zte_olt"]["vlans"].append(vlan)
            elif block_type == "bgp":
                result["bgp"].append(self._parse_bgp_block(block))
            elif block_type == "ospf":
                result["ospf"].append(self._parse_ospf_block(block))
            elif block_type == "profile":
                self._parse_profile_block(block, result["zte_olt"]["profiles"])

        result["static_routes"] = self._extract_static_routes(text)
        result["zte_olt"]["enabled"] = bool(pon_index or onu_index or result["zte_olt"]["service_ports"])
        result["zte_olt"]["pon_ports"] = sorted(pon_index.values(), key=lambda item: item["name"])
        result["zte_olt"]["onus"] = sorted(
            onu_index.values(),
            key=lambda item: (item.get("pon", ""), int(item.get("onu_id") or 0)),
        )
        for pon in result["zte_olt"]["pon_ports"]:
            pon["onu_count"] = len(pon.get("onus", []))

        result["routing"]["bgp"] = bool(result["bgp"])
        result["routing"]["ospf"] = bool(result["ospf"])
        result["routing"]["static_routes"] = bool(result["static_routes"])
        result["raw_summary"] = {
            "interfaces": len(result["interfaces"]),
            "pon_ports": len(result["zte_olt"]["pon_ports"]),
            "onus": len(result["zte_olt"]["onus"]),
            "service_ports": len(result["zte_olt"]["service_ports"]),
            "static_routes": len(result["static_routes"]),
            "vlans": len(result["vlans"]),
        }
        return result

    def _extract_hostname(self, text: str) -> str:
        for line in text.splitlines():
            match = self.RE_HOSTNAME.match(line.strip())
            if match:
                return match.group(1).strip()
        zxa10_match = re.search(r"ZXA10\s+(C\d+)", text, re.IGNORECASE)
        return zxa10_match.group(1).upper() if zxa10_match else ""

    def _split_blocks(self, text: str) -> list[dict]:
        blocks: list[dict] = []
        current_block: dict | None = None
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped in {"!", "#", "exit", "end"}:
                if current_block:
                    blocks.append(self._finalize_block(current_block))
                    current_block = None
                continue
            if self._is_static_route_line(stripped):
                blocks.append(self._make_leaf_block("static_route", stripped, line))
                continue
            if self._is_block_starter(stripped):
                if current_block:
                    blocks.append(self._finalize_block(current_block))
                current_block = {
                    "type": self._detect_block_type(stripped),
                    "header": stripped,
                    "lines": [line],
                    "raw_lines": [line],
                }
                continue
            if current_block is not None:
                current_block["lines"].append(line)
                current_block["raw_lines"].append(line)
            else:
                blocks.append(self._make_leaf_block("other", stripped, line))
        if current_block:
            blocks.append(self._finalize_block(current_block))
        return blocks

    def _is_block_starter(self, stripped: str) -> bool:
        lower = stripped.lower()
        return any(
            lower.startswith(starter)
            and (len(lower) == len(starter) or lower[len(starter)] in (" ", "\t", "_"))
            for starter in self.BLOCK_STARTERS
        )

    def _detect_block_type(self, header: str) -> str:
        lower = header.lower()
        if lower.startswith("interface"):
            return "interface"
        if lower.startswith("pon-onu-mng"):
            return "pon_onu_mng"
        if lower.startswith("vlan"):
            return "vlan"
        if lower.startswith("bgp") or lower.startswith("router bgp"):
            return "bgp"
        if lower.startswith("ospf") or lower.startswith("router ospf"):
            return "ospf"
        if lower.startswith("profile") or lower.startswith("onu-type"):
            return "profile"
        if lower.startswith("acl") or lower.startswith("ip access-list"):
            return "acl"
        return "other"

    def _make_leaf_block(self, block_type: str, header: str, line: str) -> dict:
        return {"type": block_type, "header": header, "lines": [line], "raw_lines": [line], "raw": line}

    def _finalize_block(self, block: dict) -> dict:
        block["raw"] = "\n".join(block.get("raw_lines", block.get("lines", [])))
        return block

    def _is_static_route_line(self, stripped: str) -> bool:
        lower = stripped.lower()
        return lower.startswith("ip route ") or lower.startswith("ip route-static ")

    def _parse_interface_block(self, block: dict) -> dict:
        header = block["header"]
        match = self.RE_INTERFACE.match(header)
        name = match.group(1).strip() if match else header
        interface: dict = {
            "name": name,
            "type": self._classify_interface(name),
            "description": "",
            "admin_state": "up",
            "ip_address": "",
            "ipv6_addresses": [],
            "vlan_id": "",
            "allowed_vlans": [],
            "mode": "",
            "raw": block["raw"],
        }
        for line in block.get("lines", [])[1:]:
            stripped = line.strip()
            lower = stripped.lower()
            if lower.startswith("description "):
                interface["description"] = stripped.split(" ", 1)[1].strip()
                continue
            if lower == "shutdown":
                interface["admin_state"] = "down"
                continue
            if lower in {"no shutdown", "undo shutdown"}:
                interface["admin_state"] = "up"
                continue
            if lower.startswith("ip address "):
                interface["ip_address"] = self._format_ipv4_address(stripped)
                continue
            if lower.startswith("ipv6 address "):
                address = self._parse_ipv6_address(stripped)
                if address:
                    interface["ipv6_addresses"].append(address)
                continue
            if lower.startswith("switchport mode "):
                interface["mode"] = stripped.split()[-1].lower()
                continue
            if lower.startswith("switchport vlan "):
                vlans = self._extract_vlan_ids(stripped)
                interface["allowed_vlans"].extend(vlans)
                if vlans and not interface["vlan_id"]:
                    interface["vlan_id"] = str(vlans[0])
                continue
            if lower.startswith("service-port "):
                service = self._parse_service_port_line(stripped)
                if service and service.get("vlan") and not interface["vlan_id"]:
                    interface["vlan_id"] = service["vlan"]
        return interface

    def _classify_interface(self, name: str) -> str:
        lower = name.lower()
        if lower.startswith("gpon-olt_") or lower.startswith("xgpon-olt_"):
            return "pon"
        if lower.startswith("gpon-onu_") or lower.startswith("xgpon-onu_"):
            return "onu"
        if lower.startswith(("gei_", "xgei_", "xei_", "eth_", "smartgroup")):
            return "uplink"
        if lower.startswith(("vlanif", "ve")):
            return "svi"
        if "." in name:
            return "subinterface"
        return "interface"

    def _parse_olt_interface(
        self,
        block: dict,
        interface: dict,
        olt_data: dict,
        pon_index: dict[str, dict],
        onu_index: dict[str, dict],
    ) -> None:
        name = interface["name"]
        pon_match = self.RE_PON.search(name)
        onu_match = self.RE_ONU.search(name)
        if pon_match:
            pon_id = pon_match.group(1)
            pon_entry = pon_index.setdefault(pon_id, {
                "name": name,
                "pon": pon_id,
                "description": interface.get("description", ""),
                "onus": [],
                "onu_count": 0,
                "raw": block["raw"],
            })
            self._parse_pon_onu_declarations(block, pon_id, pon_entry, onu_index)
            return
        if onu_match:
            pon_id, onu_id = onu_match.group(1), onu_match.group(2)
            onu = self._ensure_onu(onu_index, pon_id, onu_id)
            onu["interface"] = name
            onu["description"] = interface.get("description", "") or onu.get("description", "")
            onu["admin_state"] = interface.get("admin_state", "up")
            onu["raw"] = self._append_raw(onu.get("raw", ""), block["raw"])
            self._parse_onu_service_block(block, onu, olt_data)

    def _parse_pon_onu_declarations(self, block: dict, pon_id: str, pon_entry: dict, onu_index: dict[str, dict]) -> None:
        for line in block.get("lines", [])[1:]:
            stripped = line.strip()
            decl_match = self.RE_ONU_DECL.match(stripped)
            if decl_match:
                onu_id, onu_type, serial = decl_match.groups()
                onu = self._ensure_onu(onu_index, pon_id, onu_id)
                onu["type"] = onu_type
                onu["serial"] = serial
                onu["interface"] = f"gpon-onu_{pon_id}:{onu_id}"
                onu["raw"] = self._append_raw(onu.get("raw", ""), stripped)
                if onu not in pon_entry["onus"]:
                    pon_entry["onus"].append(onu)
                continue
            name_match = self.RE_ONU_NAME.match(stripped)
            if name_match:
                onu_id, onu_name = name_match.groups()
                onu = self._ensure_onu(onu_index, pon_id, onu_id)
                onu["name"] = onu_name.strip()
                onu["description"] = onu_name.strip()
                if onu not in pon_entry["onus"]:
                    pon_entry["onus"].append(onu)

    def _ensure_onu(self, onu_index: dict[str, dict], pon_id: str, onu_id: str) -> dict:
        key = f"{pon_id}:{onu_id}"
        return onu_index.setdefault(key, {
            "pon": pon_id,
            "onu_id": onu_id,
            "interface": f"gpon-onu_{pon_id}:{onu_id}",
            "name": "",
            "description": "",
            "type": "",
            "serial": "",
            "admin_state": "up",
            "tconts": [],
            "gemports": [],
            "service_ports": [],
            "raw": "",
        })

    def _parse_onu_service_block(self, block: dict, onu: dict, olt_data: dict) -> None:
        for line in block.get("lines", [])[1:]:
            stripped = line.strip()
            lower = stripped.lower()
            if lower.startswith("tcont "):
                onu["tconts"].append(self._parse_named_id_line(stripped, "tcont"))
                continue
            if lower.startswith("gemport "):
                onu["gemports"].append(self._parse_named_id_line(stripped, "gemport"))
                continue
            if lower.startswith("service-port "):
                service = self._parse_service_port_line(stripped)
                if service:
                    service["onu"] = onu["interface"]
                    onu["service_ports"].append(service)
                    olt_data["service_ports"].append(service)

    def _parse_pon_onu_mng_block(self, block: dict, olt_data: dict, onu_index: dict[str, dict]) -> None:
        header = block["header"]
        match = self.RE_ONU.search(header)
        if not match:
            return
        pon_id, onu_id = match.group(1), match.group(2)
        onu = self._ensure_onu(onu_index, pon_id, onu_id)
        onu["raw"] = self._append_raw(onu.get("raw", ""), block["raw"])
        for line in block.get("lines", [])[1:]:
            stripped = line.strip()
            lower = stripped.lower()
            if lower.startswith("service ") or lower.startswith("vlan port "):
                service = self._parse_service_port_line(stripped)
                if service:
                    service["onu"] = onu["interface"]
                    service["source"] = "pon-onu-mng"
                    onu["service_ports"].append(service)
                    olt_data["service_ports"].append(service)

    def _parse_named_id_line(self, line: str, keyword: str) -> dict:
        tokens = line.split()
        data = {"id": tokens[1] if len(tokens) > 1 else "", "raw": line}
        if "profile" in [token.lower() for token in tokens]:
            profile_index = [token.lower() for token in tokens].index("profile")
            if profile_index + 1 < len(tokens):
                data["profile"] = tokens[profile_index + 1]
        if keyword == "gemport" and "tcont" in [token.lower() for token in tokens]:
            tcont_index = [token.lower() for token in tokens].index("tcont")
            if tcont_index + 1 < len(tokens):
                data["tcont"] = tokens[tcont_index + 1]
        return data

    def _parse_service_port_line(self, line: str) -> dict:
        tokens = line.split()
        lower_tokens = [token.lower() for token in tokens]
        service = {"id": "", "vport": "", "gemport": "", "user_vlan": "", "vlan": "", "raw": line}
        if tokens:
            service["source"] = tokens[0].lower()
        if lower_tokens and lower_tokens[0] in {"service-port", "service"} and len(tokens) > 1:
            service["id"] = tokens[1]
        for key, output_key in (
            ("vport", "vport"),
            ("gemport", "gemport"),
            ("user-vlan", "user_vlan"),
            ("vlan", "vlan"),
        ):
            if key in lower_tokens:
                index = lower_tokens.index(key)
                if index + 1 < len(tokens):
                    service[output_key] = tokens[index + 1]
        if not service["vlan"]:
            vlan_ids = self._extract_vlan_ids(line)
            if vlan_ids:
                service["vlan"] = str(vlan_ids[-1])
        return service

    def _parse_vlan_block(self, block: dict) -> dict:
        header = block["header"]
        match = self.RE_VLAN.match(header)
        vlan_id = match.group(1) if match else ""
        vlan = {"vlan_id": vlan_id, "name": "", "description": "", "raw": block["raw"]}
        for line in block.get("lines", [])[1:]:
            stripped = line.strip()
            lower = stripped.lower()
            if lower.startswith("name "):
                vlan["name"] = stripped.split(" ", 1)[1].strip()
            elif lower.startswith("description "):
                vlan["description"] = stripped.split(" ", 1)[1].strip()
        return vlan

    def _parse_profile_block(self, block: dict, profiles: dict) -> None:
        header = block["header"].lower()
        if "onu" in header:
            profiles["onu_types"].append(block["header"])
        elif "tcont" in header or "dba" in header:
            profiles["tcont_profiles"].append(block["header"])
        elif "line" in header:
            profiles["line_profiles"].append(block["header"])
        elif "service" in header:
            profiles["service_profiles"].append(block["header"])
        profiles["raw_profiles"].append(block["raw"])

    def _parse_bgp_block(self, block: dict) -> dict:
        header = block["header"]
        match = self.RE_BGP.match(header)
        as_number = match.group(1) if match else ""
        peer_map: dict[str, dict] = {}
        networks: list[str] = []
        for line in block.get("lines", [])[1:]:
            stripped = line.strip()
            peer_as = re.match(r"^peer\s+([0-9a-fA-F:.]+)\s+as-number\s+(\d+)", stripped, re.IGNORECASE)
            if peer_as:
                peer_ip, remote_as = peer_as.groups()
                peer = peer_map.setdefault(peer_ip, {"ip": peer_ip, "remote_as": "", "description": "", "raw": ""})
                peer["remote_as"] = remote_as
                peer["raw"] = self._append_raw(peer.get("raw", ""), stripped)
                continue
            peer_desc = re.match(r"^peer\s+([0-9a-fA-F:.]+)\s+description\s+(.+)$", stripped, re.IGNORECASE)
            if peer_desc:
                peer_ip, description = peer_desc.groups()
                peer = peer_map.setdefault(peer_ip, {"ip": peer_ip, "remote_as": "", "description": "", "raw": ""})
                peer["description"] = description.strip()
                peer["raw"] = self._append_raw(peer.get("raw", ""), stripped)
                continue
            if stripped.lower().startswith("network "):
                networks.append(stripped.split(" ", 1)[1].strip())
        return {"as_number": as_number, "peers": list(peer_map.values()), "networks": networks, "raw": block["raw"]}

    def _parse_ospf_block(self, block: dict) -> dict:
        header = block["header"]
        match = self.RE_OSPF.match(header)
        ospf = {"process_id": match.group(1) if match else "", "router_id": "", "areas": [], "networks": [], "raw": block["raw"]}
        for line in block.get("lines", [])[1:]:
            stripped = line.strip()
            lower = stripped.lower()
            if lower.startswith("router-id "):
                ospf["router_id"] = stripped.split()[-1]
            elif lower.startswith("area "):
                ospf["areas"].append(stripped.split()[1])
            elif lower.startswith("network "):
                ospf["networks"].append(stripped.split(" ", 1)[1].strip())
        return ospf

    def _extract_static_routes(self, text: str) -> list[dict]:
        routes: list[dict] = []
        for line in text.splitlines():
            route = self._parse_static_route_line(line.strip())
            if route:
                routes.append(route)
        return routes

    def _parse_static_route_line(self, line: str) -> dict | None:
        lower = line.lower()
        if lower.startswith("ip route-static "):
            tokens = line.split()
            if len(tokens) < 5:
                return None
            network, netmask, next_hop = tokens[2], tokens[3], tokens[4]
            return {"network": network, "netmask": netmask, "next_hop": next_hop, "description": "", "vpn_instance": "", "raw": line}
        if lower.startswith("ip route "):
            tokens = line.split()
            if len(tokens) < 5:
                return None
            network, netmask, next_hop = tokens[2], tokens[3], tokens[4]
            return {"network": network, "netmask": netmask, "next_hop": next_hop, "description": "", "vpn_instance": "", "raw": line}
        return None

    def _format_ipv4_address(self, line: str) -> str:
        tokens = line.split()
        if len(tokens) < 4:
            return ""
        address, mask = tokens[2], tokens[3]
        try:
            prefix_length = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
            return f"{address}/{prefix_length}"
        except Exception:
            return f"{address} {mask}"

    def _parse_ipv6_address(self, line: str) -> dict | None:
        tokens = line.split()
        if len(tokens) < 3:
            return None
        token = tokens[2]
        if "/" in token:
            address, prefix_length = token.split("/", 1)
        else:
            address, prefix_length = token, ""
        return {"address": address, "prefix_length": prefix_length, "raw": line}

    def _extract_vlan_ids(self, line: str) -> list[int]:
        vlan_ids: list[int] = []
        for token in line.replace(",", " ").split():
            if token.isdigit():
                vlan_ids.append(int(token))
                continue
            if "-" in token:
                start, end = token.split("-", 1)
                if start.isdigit() and end.isdigit():
                    vlan_ids.extend(range(int(start), int(end) + 1))
        return vlan_ids

    def _append_raw(self, current: str, new_text: str) -> str:
        if not new_text:
            return current
        if not current:
            return new_text
        return f"{current}\n{new_text}"
