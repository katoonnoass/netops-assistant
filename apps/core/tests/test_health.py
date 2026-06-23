from django.test import TestCase

from apps.core.tests import *


class HealthCheckTests(TestCase):
    def test_health_returns_200_without_login(self):
        response = self.client.get("/health/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "ok")

    def test_health_content_type_text(self):
        response = self.client.get("/health/")
        self.assertIn("text/plain", response["Content-Type"])
