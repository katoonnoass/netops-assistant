"""Testes de configuração básica — garante que __init__ seja importado.

Este arquivo existe para garantir que Django descubra e importe
apps/core/tests/__init__.py, que desabilita autenticação para testes.
"""

from django.test import TestCase


class CoreInitTests(TestCase):
    def test_core_init_imported(self):
        """Verifica que o módulo foi carregado (auth desabilitado)."""
        from apps.core.permissions import _AUTH_DISABLED
        self.assertTrue(_AUTH_DISABLED)
