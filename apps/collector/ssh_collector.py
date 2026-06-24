from dataclasses import dataclass, field
from typing import Optional

from .security import mask_text, mask_secret
from .vendor import get_collect_command, is_supported_vendor

SAMPLE_HUAWEI_CONFIG = """#
sysname PE-01
#
interface GigabitEthernet0/0/0
 description LINK-TO-CORE
 ip address 10.0.0.1 255.255.255.252
#
interface LoopBack0
 ip address 10.255.0.1 255.255.255.255
#
ospf 1 router-id 10.255.0.1
 area 0.0.0.0
  network 10.0.0.0 0.0.0.3
  network 10.255.0.1 0.0.0.0
#
ip route-static 0.0.0.0 0.0.0.0 10.0.0.2
#
user-interface vty 0 4
 authentication-mode aaa
#
return
"""


@dataclass
class SshCollectionResult:
    device_name: str
    ip_address: str
    vendor: str
    command: str
    config_text: Optional[str] = None
    success: bool = False
    error: Optional[str] = None


class BaseSshCollectorAdapter:
    def collect_config(self, device, credential, timeout=10):
        raise NotImplementedError


class RealSshCollectorAdapter(BaseSshCollectorAdapter):
    def collect_config(self, device, credential, timeout=10):
        raise NotImplementedError(
            "Real SSH collection não implementada na Fase 1. "
            "Será implementada na Fase 3 com Netmiko."
        )


class MockSshCollectorAdapter(BaseSshCollectorAdapter):
    def __init__(self, config_samples=None):
        self.config_samples = config_samples or {
            "huawei": SAMPLE_HUAWEI_CONFIG,
            "cisco": "! Cisco IOS running-config\nhostname CORE-SW-01\n!\ninterface GigabitEthernet0/0\n ip address 192.168.0.1 255.255.255.0\n!\nend",
        }

    def collect_config(self, device, credential, timeout=10):
        vendor = device.vendor if device else "huawei"
        command = get_collect_command(vendor)
        if not command:
            return SshCollectionResult(
                device_name=device.name if device else "?",
                ip_address=device.ip_address if device else "?",
                vendor=vendor,
                command="",
                success=False,
                error=f"Vendor '{vendor}' não possui comando de coleta mapeado",
            )
        config_text = self.config_samples.get(vendor)
        if not config_text:
            return SshCollectionResult(
                device_name=device.name if device else "?",
                ip_address=device.ip_address if device else "?",
                vendor=vendor,
                command=command,
                success=False,
                error=f"Vendor '{vendor}' não possui sample config mockada",
            )
        return SshCollectionResult(
            device_name=device.name if device else "mock-device",
            ip_address=device.ip_address if device else "127.0.0.1",
            vendor=vendor,
            command=command,
            config_text=config_text,
            success=True,
        )
