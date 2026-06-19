"""WSGI config for netops_assistant project."""
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netops_assistant.settings")

application = get_wsgi_application()
