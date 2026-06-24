import ipaddress
from dataclasses import dataclass
from typing import Optional

from .vendor import detect_vendor_from_sysdescr

# ── OIDs ──────────────────────────────────────────────────────────
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

MAX_SUBNET_PREFIX = 24  # /24 is the largest allowed by default


# ── Data class ────────────────────────────────────────────────────
@dataclass
class SnmpDiscoveryResult:
    ip_address: str
    sys_name: Optional[str] = None
    sys_descr: Optional[str] = None
    sys_object_id: Optional[str] = None
    vendor: str = "unknown"
    success: bool = False
    error: Optional[str] = None


# ── Mock table ────────────────────────────────────────────────────
MOCK_DISCOVERY_TABLE = {
    "192.168.1.1": SnmpDiscoveryResult(
        ip_address="192.168.1.1",
        sys_name="PE-01",
        sys_descr="Huawei Versatile Routing Platform Software VRP (R) V800R012C00",
        sys_object_id="1.3.6.1.4.1.2011.1",
        vendor="huawei",
        success=True,
    ),
    "192.168.1.2": SnmpDiscoveryResult(
        ip_address="192.168.1.2",
        sys_name="CORE-SW-01",
        sys_descr="Cisco IOS-XE Software, Version 17.3.1a",
        sys_object_id="1.3.6.1.4.1.9.1.1",
        vendor="cisco",
        success=True,
    ),
}


# ── Adapter base ──────────────────────────────────────────────────
class BaseSnmpAdapter:
    def get_system_info(self, ip_address, community="public", version="v2c", timeout=5):
        raise NotImplementedError


# ── Real adapter (PySNMP) ─────────────────────────────────────────
class RealSnmpAdapter(BaseSnmpAdapter):
    def get_system_info(self, ip_address, community="public", version="v2c", timeout=5):
        if version != "v2c":
            return SnmpDiscoveryResult(
                ip_address=ip_address,
                success=False,
                error=f"Versão SNMP '{version}' não suportada nesta fase (apenas v2c).",
            )
        if not community:
            return SnmpDiscoveryResult(
                ip_address=ip_address,
                success=False,
                error="SNMP community não configurada.",
            )
        try:
            sys_descr = _snmp_get(ip_address, OID_SYS_DESCR, community, timeout)
            sys_obj_id = _snmp_get(ip_address, OID_SYS_OBJECT_ID, community, timeout)
            sys_name = _snmp_get(ip_address, OID_SYS_NAME, community, timeout)
        except Exception as e:
            msg = str(e)
            # Filtra comunidade do erro (caso vaze em exception rara)
            if community and community in msg:
                msg = msg.replace(community, "****")
            return SnmpDiscoveryResult(
                ip_address=ip_address,
                success=False,
                error=msg[:300],
            )

        if not sys_descr and not sys_obj_id:
            return SnmpDiscoveryResult(
                ip_address=ip_address,
                success=False,
                error="Sem resposta SNMP (timeout ou comunidade inválida)",
            )

        vendor = detect_vendor_from_sysdescr(sys_descr, sys_obj_id)

        return SnmpDiscoveryResult(
            ip_address=ip_address,
            sys_name=sys_name or None,
            sys_descr=sys_descr or None,
            sys_object_id=sys_obj_id or None,
            vendor=vendor,
            success=True,
        )


def _snmp_get(ip_address, oid, community, timeout):
    """Thin PySNMP wrapper — returns value string or None on noSuchInstance."""
    from pysnmp.hlapi import CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget, getCmd

    error_indication, error_status, error_index, var_binds = next(
        getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),  # SNMPv2c
            UdpTransportTarget((ip_address, 161), timeout=timeout, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
    )

    if error_indication:
        raise ConnectionError(str(error_indication))

    if error_status:
        raise ConnectionError(f"SNMP error: {error_status}")

    if not var_binds:
        return None

    val = var_binds[0][1]
    if val is None or str(val) == "0.0":
        return None

    return str(val)


# ── Mock adapter ──────────────────────────────────────────────────
class MockSnmpAdapter(BaseSnmpAdapter):
    def __init__(self, discovery_table=None):
        self.discovery_table = discovery_table or MOCK_DISCOVERY_TABLE

    def get_system_info(self, ip_address, community="public", version="v2c", timeout=5):
        result = self.discovery_table.get(ip_address)
        if result:
            return result
        return SnmpDiscoveryResult(
            ip_address=ip_address,
            success=False,
            error="IP não encontrado na tabela mock",
        )


# ── Subnet expansion ──────────────────────────────────────────────
def expand_cidr(cidr):
    """Expand a CIDR string into a sorted list of IP strings.

    Respects MAX_SUBNET_PREFIX (/24) by default.
    Use allow_large=True to bypass the limit.
    """
    if not cidr or "/" not in cidr:
        return [cidr] if cidr else []
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise ValueError(f"CIDR inválido '{cidr}': {e}") from e

    prefix = net.prefixlen
    if prefix < MAX_SUBNET_PREFIX:
        raise ValueError(
            f"Subnet {cidr} tem prefixo /{prefix}, que é maior que o limite de /{MAX_SUBNET_PREFIX}. "
            f"Use --allow-large-subnet para permitir."
        )

    # Return usable host IPs (skip network/broadcast for IPv4)
    if net.version == 4:
        return [str(h) for h in net.hosts()]
    else:
        return [str(h) for h in net]


def validate_subnet_size(cidr, allow_large=False):
    """Return True if the subnet is allowed, raise otherwise."""
    if not cidr or "/" not in cidr:
        return True
    net = ipaddress.ip_network(cidr, strict=False)
    if not allow_large and net.prefixlen < MAX_SUBNET_PREFIX:
        raise ValueError(
            f"Subnet {cidr} tem prefixo /{net.prefixlen} (> /{MAX_SUBNET_PREFIX}). "
            f"Use --allow-large-subnet para permitir."
        )
    return True
