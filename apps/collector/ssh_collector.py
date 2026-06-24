from dataclasses import dataclass
from typing import Optional

from netmiko import ConnectHandler

from .security import decrypt_value, mask_secret, mask_text
from .vendor import get_collect_command, get_netmiko_device_type, is_supported_vendor

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
        vendor = device.vendor if device else ""
        netmiko_type = get_netmiko_device_type(vendor)
        command = get_collect_command(vendor)

        if not netmiko_type or not command:
            return SshCollectionResult(
                device_name=device.name if device else "?",
                ip_address=device.ip_address if device else "?",
                vendor=vendor,
                command="",
                success=False,
                error=f"Vendor '{vendor}' não suportado para coleta SSH.",
            )

        if not credential:
            return SshCollectionResult(
                device_name=device.name if device else "?",
                ip_address=device.ip_address if device else "?",
                vendor=vendor,
                command=command,
                success=False,
                error="Nenhuma credencial disponível para coleta SSH.",
            )

        if not credential.username:
            return SshCollectionResult(
                device_name=device.name if device else "?",
                ip_address=device.ip_address if device else "?",
                vendor=vendor,
                command=command,
                success=False,
                error="Credencial sem usuário configurado.",
            )

        password = decrypt_value(credential.encrypted_password) if credential.encrypted_password else ""
        enable_secret = decrypt_value(credential.encrypted_enable_secret) if credential.encrypted_enable_secret else ""

        if not password:
            return SshCollectionResult(
                device_name=device.name if device else "?",
                ip_address=device.ip_address if device else "?",
                vendor=vendor,
                command=command,
                success=False,
                error="Credencial sem senha configurada.",
            )

        device_params = {
            "device_type": netmiko_type,
            "host": str(device.ip_address) if device.ip_address else "",
            "username": credential.username,
            "password": password,
            "port": getattr(device, "ssh_port", 22) or 22,
            "timeout": timeout,
            "conn_timeout": timeout,
            "banner_timeout": timeout,
            "auth_timeout": timeout,
            "global_delay_factor": 2,
        }

        if enable_secret:
            device_params["secret"] = enable_secret

        if not device_params["host"]:
            return SshCollectionResult(
                device_name=device.name if device else "?",
                ip_address="",
                vendor=vendor,
                command=command,
                success=False,
                error="Device sem endereço IP configurado.",
            )

        try:
            conn = ConnectHandler(**device_params)
            if enable_secret:
                conn.enable()
            config_text = conn.send_command(command, read_timeout=timeout)
            conn.disconnect()
        except Exception as e:
            msg = str(e)[:500]
            for secret in [password, enable_secret, credential.username]:
                if secret and secret in msg:
                    msg = msg.replace(secret, mask_secret(secret))
            return SshCollectionResult(
                device_name=device.name if device else "?",
                ip_address=str(device.ip_address) if device.ip_address else "?",
                vendor=vendor,
                command=command,
                success=False,
                error=msg,
            )

        if not config_text or not config_text.strip():
            return SshCollectionResult(
                device_name=device.name if device else "?",
                ip_address=str(device.ip_address) if device.ip_address else "?",
                vendor=vendor,
                command=command,
                success=False,
                error="Configuração vazia retornada pelo equipamento.",
            )

        return SshCollectionResult(
            device_name=device.name if device else "?",
            ip_address=str(device.ip_address) if device.ip_address else "?",
            vendor=vendor,
            command=command,
            config_text=config_text,
            success=True,
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
