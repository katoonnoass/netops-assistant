from dataclasses import dataclass, field
from typing import Optional

from .vendor import VENDOR_MAP, detect_vendor_from_sysdescr


@dataclass
class SnmpDiscoveryResult:
    ip_address: str
    sys_name: Optional[str] = None
    sys_descr: Optional[str] = None
    sys_object_id: Optional[str] = None
    vendor: str = "unknown"
    success: bool = False
    error: Optional[str] = None


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


class BaseSnmpAdapter:
    def get_system_info(self, ip_address, community="public", version="v2c", timeout=5):
        raise NotImplementedError


class RealSnmpAdapter(BaseSnmpAdapter):
    def get_system_info(self, ip_address, community="public", version="v2c", timeout=5):
        raise NotImplementedError(
            "Real SNMP discovery não implementado na Fase 1. "
            "Será implementado na Fase 2 com PySNMP."
        )


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


def discover_subnet(profile, adapter=None, dry_run=False):
    if dry_run:
        return _dry_run_discovery(profile)
    if adapter is None:
        adapter = MockSnmpAdapter()
    results = []
    subnets = profile.subnets or []
    for subnet in subnets:
        ips = _expand_cidr_mock(subnet)
        for ip in ips:
            result = adapter.get_system_info(ip)
            if result.success:
                vendor = result.vendor or detect_vendor_from_sysdescr(
                    result.sys_descr, result.sys_object_id
                )
                result.vendor = vendor
            results.append(result)
    return results


def _dry_run_discovery(profile):
    from .services import _mask_profile_secrets

    secrets = _mask_profile_secrets(profile)
    return [
        f"[DRY-RUN] Descoberta SNMP no perfil '{profile.name}'"
        f" subnets={profile.subnets}"
        f" timeout={profile.timeout}s"
        f" community={secrets.get('snmp_community', '****')}"
        f" versão={profile.snmp_version}"
    ]


def _expand_cidr_mock(cidr):
    if not cidr or "/" not in cidr:
        return [cidr] if cidr else []
    prefix, bits = cidr.split("/")
    bits = int(bits)
    if bits >= 24 or bits < 0:
        return [prefix[:-2] + ".1"] if prefix.endswith(".0") else [prefix]
    return [prefix]
