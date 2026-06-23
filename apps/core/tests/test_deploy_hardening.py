from pathlib import Path

from django.test import SimpleTestCase


def _read(path):
    return path.read_text(encoding="utf-8")


class DeployHardeningFilesTests(SimpleTestCase):
    def setUp(self):
        self.base = Path(__file__).resolve().parent.parent.parent.parent

    def test_docker_compose_has_web_healthcheck(self):
        content = _read(self.base / "docker-compose.yml")
        self.assertIn("healthcheck:", content)
        self.assertIn("web:", content)
        idx = content.index("web:")
        section = content[idx:idx + 600]
        self.assertIn("healthcheck", section)

    def test_docker_compose_has_nginx_healthcheck(self):
        content = _read(self.base / "docker-compose.yml")
        self.assertIn("nginx:", content)
        idx = content.index("nginx:")
        section = content[idx:idx + 600]
        self.assertIn("healthcheck", section)

    def test_backup_script_exists(self):
        self.assertTrue((self.base / "scripts" / "docker_backup.sh").exists())

    def test_backup_script_has_retention(self):
        content = _read(self.base / "scripts" / "docker_backup.sh")
        self.assertIn("BACKUP_RETENTION_DAYS", content)
        self.assertIn("--include-raw-config", content)

    def test_backup_script_has_compress(self):
        content = _read(self.base / "scripts" / "docker_backup.sh")
        self.assertIn("gzip", content)

    def test_update_script_exists(self):
        self.assertTrue((self.base / "scripts" / "docker_update.sh").exists())

    def test_update_script_has_migrate(self):
        content = _read(self.base / "scripts" / "docker_update.sh")
        self.assertIn("migrate", content)
        self.assertIn("collectstatic", content)

    def test_backup_cron_doc_exists(self):
        self.assertTrue((self.base / "docs" / "deploy" / "backup_cron.md").exists())

    def test_backup_cron_doc_has_crontab(self):
        content = _read(self.base / "docs" / "deploy" / "backup_cron.md")
        self.assertIn("crontab", content.lower())

    def test_checklist_doc_exists(self):
        self.assertTrue((self.base / "docs" / "deploy" / "checklist.md").exists())

    def test_checklist_has_update_section(self):
        content = _read(self.base / "docs" / "deploy" / "checklist.md")
        self.assertIn("Atualiza", content)

    def test_https_example_exists(self):
        self.assertTrue((self.base / "docker" / "nginx" / "https.example.conf").exists())

    def test_https_example_has_ssl_placeholders(self):
        content = _read(self.base / "docker" / "nginx" / "https.example.conf")
        self.assertIn("ssl_certificate", content)
        self.assertIn("ssl_certificate_key", content)

    def test_env_example_has_csrf_trusted_origins(self):
        content = _read(self.base / ".env.example")
        self.assertIn("CSRF_TRUSTED_ORIGINS", content)

    def test_env_example_has_strong_secret_comment(self):
        content = _read(self.base / ".env.example")
        self.assertIn("DJANGO_SECRET_KEY", content)
        self.assertIn("change-me-generate", content)


class ReadmeHardeningTests(SimpleTestCase):
    def test_readme_contains_hardening_section(self):
        readme = Path(__file__).resolve().parent.parent.parent.parent / "README.md"
        if readme.exists():
            content = _read(readme)
            self.assertIn("Hardening", content)
