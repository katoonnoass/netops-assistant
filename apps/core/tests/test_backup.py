import json
import tempfile
from pathlib import Path

from django.core.management import call_command
from django.test import TestCase

from apps.config_archive.models import ConfigSnapshot


class OperationalBackupTests(TestCase):
    def test_backup_excludes_raw_config_by_default(self):
        ConfigSnapshot.objects.create(
            raw_config="local-user admin password cipher SENSITIVE-VALUE",
            vendor="huawei",
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "backup.json"
            call_command("export_operational_backup", output=str(output_path))
            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertFalse(payload["include_raw_config"])
        self.assertNotIn("raw_config", payload["data"]["snapshots"][0])
        self.assertNotIn("SENSITIVE-VALUE", json.dumps(payload))

    def test_backup_with_raw_config_is_explicit(self):
        ConfigSnapshot.objects.create(
            raw_config="sysname BACKUP-RAW",
            vendor="huawei",
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "backup.json"
            call_command(
                "export_operational_backup",
                output=str(output_path),
                include_raw=True,
            )
            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertTrue(payload["include_raw_config"])
        self.assertEqual(
            payload["data"]["snapshots"][0]["raw_config"],
            "sysname BACKUP-RAW",
        )
