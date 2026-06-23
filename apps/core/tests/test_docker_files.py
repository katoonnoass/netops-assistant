import os
from pathlib import Path

from django.test import SimpleTestCase


class DockerFilesExistTests(SimpleTestCase):
    def setUp(self):
        self.base = Path(__file__).resolve().parent.parent.parent.parent

    def test_dockerfile_exists(self):
        self.assertTrue((self.base / "Dockerfile").exists())

    def test_docker_compose_yml_exists(self):
        self.assertTrue((self.base / "docker-compose.yml").exists())

    def test_docker_compose_override_yml_exists(self):
        self.assertTrue((self.base / "docker-compose.override.yml").exists())

    def test_dockerenv_example_exists(self):
        self.assertTrue((self.base / ".env.example").exists())

    def test_dockerenv_example_has_secret_key(self):
        content = (self.base / ".env.example").read_text()
        self.assertIn("DJANGO_SECRET_KEY", content)
        self.assertIn("DATABASE_URL", content)

    def test_dockerignore_exists(self):
        self.assertTrue((self.base / ".dockerignore").exists())

    def test_docker_entrypoint_exists(self):
        self.assertTrue((self.base / "docker" / "entrypoint.sh").exists())

    def test_nginx_config_exists(self):
        self.assertTrue((self.base / "docker" / "nginx" / "default.conf").exists())

    def test_docker_compose_has_services(self):
        content = (self.base / "docker-compose.yml").read_text()
        self.assertIn("  web:", content)
        self.assertIn("  db:", content)
        self.assertIn("  nginx:", content)

    def test_dockerfile_contains_gunicorn(self):
        content = (self.base / "Dockerfile").read_text()
        self.assertIn("gunicorn", content)

    def test_requirements_has_gunicorn_and_psycopg(self):
        content = (self.base / "requirements.txt").read_text()
        self.assertIn("gunicorn", content)
        self.assertIn("psycopg", content)

    def test_scripts_backup_exists(self):
        self.assertTrue((self.base / "scripts" / "docker_backup.sh").exists())


class DjangoSettingsEnvTests(SimpleTestCase):
    def test_settings_has_static_root(self):
        from django.conf import settings
        self.assertTrue(hasattr(settings, "STATIC_ROOT"))

    def test_settings_has_media_root(self):
        from django.conf import settings
        self.assertTrue(hasattr(settings, "MEDIA_ROOT"))

    def test_settings_has_csrf_trusted_origins(self):
        from django.conf import settings
        self.assertTrue(hasattr(settings, "CSRF_TRUSTED_ORIGINS"))
