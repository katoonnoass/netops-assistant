"""Management command para exportar backup operacional do NetOps Assistant.

Uso:
    python manage.py export_operational_backup --output backup.json
    python manage.py export_operational_backup --output backup_full.json --include-raw-config
"""

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.analysis.models import (
    AnalysisIssue,
    ConfigComparison,
    DetectedCircuit,
    DetectedService,
    ParsedConfig,
)
from apps.config_archive.models import ConfigSnapshot
from apps.core.models import AuditLog
from apps.devices.models import Device


def _serialize_value(val):
    """Serialize values for JSON export."""
    if isinstance(val, datetime):
        return val.isoformat()
    if hasattr(val, 'isoformat'):
        return val.isoformat()
    return val


def _model_to_dict(instance, fields: list[str]) -> dict:
    """Convert a model instance to a dict with specified fields."""
    result = {}
    for f in fields:
        val = getattr(instance, f, None)
        result[f] = _serialize_value(val) if not isinstance(val, (str, int, float, bool, type(None))) else val
    return result


class Command(BaseCommand):
    help = "Exporta dados operacionais como JSON para backup manual"

    def add_arguments(self, parser):
        parser.add_argument("--output", "-o", required=True, help="Caminho do arquivo JSON de saída")
        parser.add_argument(
            "--include-raw-config",
            action="store_true",
            dest="include_raw",
            help="Inclui configurações brutas (pode conter dados sensíveis)",
        )

    def handle(self, *args, **options):
        output_path = options["output"]
        include_raw = options["include_raw"]

        export = {
            "exported_at": timezone.now().isoformat(),
            "version": "1.0",
            "include_raw_config": include_raw,
            "data": {},
        }

        # Devices
        devices = []
        for d in Device.objects.all():
            devices.append(_model_to_dict(d, [
                "pk", "name", "vendor", "platform", "role", "site",
                "ip_address", "hostname", "description", "created_at", "updated_at",
            ]))
        export["data"]["devices"] = devices
        self.stdout.write(f"  Dispositivos: {len(devices)}")

        # Config Snapshots
        snapshots = []
        qs = ConfigSnapshot.objects.all()
        base_fields = [
            "pk", "device_id", "name", "config_hash", "vendor", "source",
            "captured_at", "is_baseline", "notes", "description", "created_at",
        ]
        for snap in qs:
            entry = _model_to_dict(snap, base_fields)
            if include_raw:
                entry["raw_config"] = snap.raw_config
            snapshots.append(entry)
        export["data"]["snapshots"] = snapshots
        self.stdout.write(f"  Snapshots: {len(snapshots)}" + (" (com configs brutas)" if include_raw else ""))

        # Parsed Configs
        parsed_configs = []
        for pc in ParsedConfig.objects.all():
            entry = _model_to_dict(pc, ["pk", "snapshot_id", "parser_version", "created_at"])
            # Include parsed_data keys only (not full data, to keep size manageable)
            entry["parsed_data_keys"] = list(pc.parsed_data.keys()) if isinstance(pc.parsed_data, dict) else []
            parsed_configs.append(entry)
        export["data"]["parsed_configs"] = parsed_configs
        self.stdout.write(f"  Análises: {len(parsed_configs)}")

        # Detected Circuits
        circuits = []
        for c in DetectedCircuit.objects.all():
            entry = _model_to_dict(c, ["pk", "snapshot_id", "circuit_type", "description", "created_at"])
            entry["details"] = c.details
            circuits.append(entry)
        export["data"]["circuits"] = circuits
        self.stdout.write(f"  Circuitos: {len(circuits)}")

        # Detected Services
        services = []
        for s in DetectedService.objects.all():
            entry = _model_to_dict(s, ["pk", "snapshot_id", "service_type", "name", "description", "confidence", "created_at"])
            entry["metadata"] = s.metadata
            services.append(entry)
        export["data"]["services"] = services
        self.stdout.write(f"  Serviços: {len(services)}")

        # Analysis Issues
        issues = []
        for i in AnalysisIssue.objects.all():
            entry = _model_to_dict(i, ["pk", "snapshot_id", "severity", "category", "code", "title", "description", "created_at"])
            entry["metadata"] = i.metadata
            issues.append(entry)
        export["data"]["issues"] = issues
        self.stdout.write(f"  Issues: {len(issues)}")

        # Config Comparisons
        comparisons = []
        for c in ConfigComparison.objects.all():
            comparisons.append(_model_to_dict(c, ["pk", "base_snapshot_id", "target_snapshot_id", "title", "summary", "created_at"]))
        export["data"]["comparisons"] = comparisons
        self.stdout.write(f"  Comparações: {len(comparisons)}")

        # Audit Logs
        audit_logs = []
        for al in AuditLog.objects.all():
            audit_logs.append(_model_to_dict(al, [
                "pk", "user_id", "action", "object_type", "object_id",
                "description", "ip_address", "created_at",
            ]))
        export["data"]["audit_logs"] = audit_logs
        self.stdout.write(f"  Logs de auditoria: {len(audit_logs)}")

        destination = Path(output_path).expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                json.dump(export, temporary_file, indent=2, ensure_ascii=False)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.replace(temporary_path, destination)
        finally:
            if temporary_path and temporary_path.exists():
                temporary_path.unlink()

        self.stdout.write(self.style.SUCCESS(
            f"\nBackup exportado: {destination}"
        ))
