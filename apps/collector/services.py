import logging
from datetime import datetime

from django.utils import timezone

from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device

from .discovery import MockSnmpAdapter, SnmpDiscoveryResult, discover_subnet as _discover
from .models import CollectorRun, CollectorTask, DiscoveryProfile
from .security import mask_secret
from .ssh_collector import MockSshCollectorAdapter, SshCollectionResult
from .vendor import detect_vendor_from_sysdescr, get_collect_command

logger = logging.getLogger(__name__)


def _mask_profile_secrets(profile):
    secrets = {}
    if profile.snmp_community:
        secrets["snmp_community"] = mask_secret(profile.snmp_community)
    if profile.credential:
        if profile.credential.snmp_community:
            secrets["credential_snmp_community"] = mask_secret(profile.credential.snmp_community)
        if profile.credential.username:
            secrets["username"] = profile.credential.username
    return secrets


def _create_task(run, action, ip_address=None, device=None):
    return CollectorTask.objects.create(
        run=run,
        action=action,
        ip_address=ip_address,
        device=device,
        status=CollectorTask.Status.PENDING,
    )


def run_discovery(profile_id=None, profile=None, adapter=None, dry_run=False):
    if profile is None:
        profile = DiscoveryProfile.objects.get(pk=profile_id)
    if not profile.is_active:
        raise ValueError(f"Perfil '{profile.name}' está inativo.")

    if dry_run:
        return _dry_run(profile, "descoberta SNMP")

    run = CollectorRun.objects.create(
        profile=profile,
        status=CollectorRun.Status.RUNNING,
    )

    if adapter is None:
        adapter = MockSnmpAdapter()

    try:
        subnets = profile.subnets or []
        for subnet in subnets:
            ips = _mock_expand_cidr(subnet)
            for ip in ips:
                task = _create_task(run, CollectorTask.Action.SNMP_DISCOVERY, ip_address=ip)
                task.status = CollectorTask.Status.RUNNING
                task.started_at = timezone.now()
                try:
                    result = adapter.get_system_info(
                        ip,
                        community=profile.snmp_community or "public",
                        version=profile.snmp_version,
                        timeout=profile.timeout,
                    )
                    if result.success:
                        vendor = result.vendor or detect_vendor_from_sysdescr(
                            result.sys_descr, result.sys_object_id
                        )
                        device, _ = Device.objects.get_or_create(
                            name=result.sys_name or ip,
                            defaults={
                                "ip_address": ip,
                                "vendor": vendor if vendor != "unknown" else "other",
                                "hostname": result.sys_name or "",
                                "last_discovered_at": timezone.now(),
                            },
                        )
                        if not device.last_discovered_at:
                            device.last_discovered_at = timezone.now()
                            device.save(update_fields=["last_discovered_at"])
                        task.device = device
                        task.status = CollectorTask.Status.SUCCESS
                        run.discovered_count += 1
                        log_parts = [f"Descoberto: {result.sys_name} ({ip}) vendor={vendor}"]
                        if result.sys_descr:
                            log_parts.append(f"sysDescr={result.sys_descr[:100]}")
                        task.log = "\n".join(log_parts)
                    else:
                        task.status = CollectorTask.Status.FAILED
                        task.error = result.error or "Sem resposta SNMP"
                        run.failed_count += 1
                        task.log = f"Falha SNMP em {ip}: {task.error}"
                except Exception as e:
                    task.status = CollectorTask.Status.FAILED
                    task.error = str(e)[:500]
                    run.failed_count += 1
                    task.log = f"Erro SNMP em {ip}: {task.error}"
                finally:
                    task.finished_at = timezone.now()
                    task.save(update_fields=[
                        "status", "device", "log", "error", "started_at", "finished_at"
                    ])

        if run.failed_count > 0 and run.discovered_count > 0:
            run.status = CollectorRun.Status.PARTIAL
        elif run.failed_count > 0:
            run.status = CollectorRun.Status.FAILED
        else:
            run.status = CollectorRun.Status.SUCCESS
    except Exception as e:
        run.status = CollectorRun.Status.FAILED
        run.summary = f"Erro geral: {e}"
        logger.exception("Erro na descoberta SNMP")
    finally:
        run.finished_at = timezone.now()
        run.save(update_fields=[
            "status", "discovered_count", "failed_count", "summary", "finished_at"
        ])

    return run


def run_collection(profile=None, device=None, adapter=None, dry_run=False, analyze=False):
    if profile is None and device is None:
        raise ValueError("Informe profile ou device.")
    if dry_run:
        target = profile.name if profile else device.name
        return _dry_run(profile or device, f"coleta SSH de {target}")

    run = CollectorRun.objects.create(
        profile=profile,
        status=CollectorRun.Status.RUNNING,
    )

    if adapter is None:
        adapter = MockSshCollectorAdapter()

    devices_qs = _resolve_devices(profile, device)
    try:
        for dev in devices_qs:
            if not dev.collector_enabled:
                task = _create_task(run, CollectorTask.Action.SSH_COLLECT, ip_address=dev.ip_address, device=dev)
                task.status = CollectorTask.Status.SKIPPED
                task.log = f"Coleta desabilitada para {dev.name}"
                task.finished_at = timezone.now()
                task.save()
                continue

            task = _create_task(run, CollectorTask.Action.SSH_COLLECT, ip_address=dev.ip_address, device=dev)
            task.status = CollectorTask.Status.RUNNING
            task.started_at = timezone.now()
            try:
                credential = _get_credential(profile, dev)
                result = adapter.collect_config(dev, credential, timeout=profile.timeout if profile else 10)
                if result.success and result.config_text:
                    snapshot = ConfigSnapshot.objects.create(
                        device=dev,
                        raw_config=result.config_text,
                        vendor=dev.vendor,
                        source="auto",
                    )
                    task.device = dev
                    task.status = CollectorTask.Status.SUCCESS
                    run.collected_count += 1
                    task.log = f"Coletado {len(result.config_text)} bytes de {dev.name} ({dev.ip_address})"

                    if analyze:
                        from apps.analysis.services import analyze_config_snapshot
                        try:
                            analyze_config_snapshot(snapshot)
                            run.analyzed_count += 1
                            task.log += "\nAnálise concluída"
                        except Exception as e:
                            task.log += f"\nErro na análise: {e}"
                            run.failed_count += 1
                else:
                    task.status = CollectorTask.Status.FAILED
                    task.error = result.error or "Config vazia"
                    run.failed_count += 1
                    task.log = f"Falha na coleta de {dev.name}: {task.error}"
            except Exception as e:
                task.status = CollectorTask.Status.FAILED
                task.error = str(e)[:500]
                run.failed_count += 1
                task.log = f"Erro na coleta de {dev.name}: {task.error}"
            finally:
                task.finished_at = timezone.now()
                task.save(update_fields=[
                    "status", "device", "log", "error", "started_at", "finished_at"
                ])

        if run.failed_count > 0 and run.collected_count > 0:
            run.status = CollectorRun.Status.PARTIAL
        elif run.failed_count > 0:
            run.status = CollectorRun.Status.FAILED
        else:
            run.status = CollectorRun.Status.SUCCESS
    except Exception as e:
        run.status = CollectorRun.Status.FAILED
        run.summary = f"Erro geral: {e}"
        logger.exception("Erro na coleta SSH")
    finally:
        run.finished_at = timezone.now()
        run.save(update_fields=[
            "status", "collected_count", "analyzed_count", "failed_count",
            "summary", "finished_at",
        ])

    return run


def run_full_collector(profile, dry_run=False, discover=True, collect=True, analyze=False):
    if dry_run:
        return _dry_run(profile, "execução completa")

    run = None
    if discover:
        run = run_discovery(profile=profile, dry_run=False)
    if collect:
        run = run_collection(profile=profile, dry_run=False, analyze=analyze)
    return run


def _resolve_devices(profile, device):
    if device:
        return Device.objects.filter(pk=device.pk)
    if profile:
        return Device.objects.filter(collector_enabled=True)
    return Device.objects.none()


def _get_credential(profile, device):
    if profile and profile.credential:
        return profile.credential
    return None


def _dry_run(target, action):
    return [
        f"[DRY-RUN] {action}",
        f"  Nenhuma conexão real será realizada.",
        f"  Nenhum Device será criado ou alterado.",
        f"  Nenhum ConfigSnapshot será criado.",
    ]


def _mock_expand_cidr(cidr):
    if not cidr or "/" not in cidr:
        return [cidr] if cidr else []
    prefix, bits = cidr.split("/")
    bits = int(bits)
    if bits >= 24 or bits < 0:
        return [prefix[:-2] + ".1"] if prefix.endswith(".0") else [prefix]
    return [prefix]
