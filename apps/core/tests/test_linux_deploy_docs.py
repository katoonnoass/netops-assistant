from pathlib import Path

from django.test import SimpleTestCase, override_settings


def _read(path):
    return path.read_text(encoding="utf-8")


class LinuxValidationDocTests(SimpleTestCase):
    def setUp(self):
        self.base = Path(__file__).resolve().parent.parent.parent.parent
        self.doc = self.base / "docs" / "deploy" / "linux_validation.md"

    def test_linux_validation_doc_exists(self):
        self.assertTrue(self.doc.exists())

    def test_linux_validation_contains_compose_config(self):
        content = _read(self.doc)
        self.assertIn("docker compose config", content)

    def test_linux_validation_contains_compose_up(self):
        content = _read(self.doc)
        self.assertIn("docker compose up -d", content)

    def test_linux_validation_contains_health_curl(self):
        content = _read(self.doc)
        self.assertIn("curl http://localhost/health/", content)


class EnvProductionExampleTests(SimpleTestCase):
    def setUp(self):
        self.base = Path(__file__).resolve().parent.parent.parent.parent
        self.envprod = self.base / ".env.production.example"

    def test_env_production_example_exists(self):
        self.assertTrue(self.envprod.exists())

    def test_env_production_debug_false(self):
        content = _read(self.envprod)
        self.assertIn("DJANGO_DEBUG=False", content)

    def test_env_production_allowed_hosts(self):
        content = _read(self.envprod)
        self.assertIn("DJANGO_ALLOWED_HOSTS", content)

    def test_env_production_csrf_trusted_origins(self):
        content = _read(self.envprod)
        self.assertIn("DJANGO_CSRF_TRUSTED_ORIGINS", content)

    def test_env_production_has_security_flags(self):
        content = _read(self.envprod)
        self.assertIn("SECURE_SSL_REDIRECT", content)
        self.assertIn("SESSION_COOKIE_SECURE", content)
        self.assertIn("CSRF_COOKIE_SECURE", content)
        self.assertIn("SECURE_HSTS_SECONDS", content)

    def test_env_production_has_backup_retention(self):
        content = _read(self.envprod)
        self.assertIn("BACKUP_RETENTION_DAYS", content)


class DockerSmokeScriptTests(SimpleTestCase):
    def setUp(self):
        self.base = Path(__file__).resolve().parent.parent.parent.parent
        self.script = self.base / "scripts" / "docker_smoke_test.sh"

    def test_smoke_script_exists(self):
        self.assertTrue(self.script.exists())

    def test_smoke_script_has_compose_config(self):
        content = _read(self.script)
        self.assertIn("docker compose config", content)

    def test_smoke_script_has_set_e(self):
        content = _read(self.script)
        self.assertIn("set -e", content)

    def test_smoke_script_has_health_curl(self):
        content = _read(self.script)
        self.assertIn("curl", content)
        self.assertIn("health", content)


class ReadmeTestCountTests(SimpleTestCase):
    def setUp(self):
        self.base = Path(__file__).resolve().parent.parent.parent.parent
        self.readme = self.base / "README.md"

    def test_readme_no_1265(self):
        content = _read(self.readme)
        self.assertNotIn("1265 testes", content)

    def test_readme_has_1465(self):
        content = _read(self.readme)
        self.assertIn("1465 testes", content)


class SecuritySettingsEnvTests(SimpleTestCase):
    @override_settings(
        SECURE_SSL_REDIRECT=True,
        SESSION_COOKIE_SECURE=True,
        CSRF_COOKIE_SECURE=True,
        SECURE_HSTS_SECONDS=31536000,
        SECURE_HSTS_INCLUDE_SUBDOMAINS=True,
        SECURE_HSTS_PRELOAD=True,
    )
    def test_security_flags_can_be_enabled(self):
        from django.conf import settings
        self.assertTrue(settings.SECURE_SSL_REDIRECT)
        self.assertTrue(settings.SESSION_COOKIE_SECURE)
        self.assertTrue(settings.CSRF_COOKIE_SECURE)
        self.assertEqual(settings.SECURE_HSTS_SECONDS, 31536000)
        self.assertTrue(settings.SECURE_HSTS_INCLUDE_SUBDOMAINS)
        self.assertTrue(settings.SECURE_HSTS_PRELOAD)

    @override_settings(
        SECURE_SSL_REDIRECT=False,
        SESSION_COOKIE_SECURE=False,
        CSRF_COOKIE_SECURE=False,
        SECURE_HSTS_SECONDS=0,
        SECURE_HSTS_INCLUDE_SUBDOMAINS=False,
        SECURE_HSTS_PRELOAD=False,
    )
    def test_security_flags_default_to_safe_dev(self):
        from django.conf import settings
        self.assertFalse(settings.SECURE_SSL_REDIRECT)
        self.assertFalse(settings.SESSION_COOKIE_SECURE)
        self.assertFalse(settings.CSRF_COOKIE_SECURE)
        self.assertEqual(settings.SECURE_HSTS_SECONDS, 0)
        self.assertFalse(settings.SECURE_HSTS_INCLUDE_SUBDOMAINS)
        self.assertFalse(settings.SECURE_HSTS_PRELOAD)
