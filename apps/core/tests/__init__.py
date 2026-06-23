"""Test helpers — fornece funções para testes.

Importar de um arquivo de teste dispara disable_auth_for_tests()
automaticamente, já que os decorators de view são avaliados
em tempo de importação das views (durante URL resolution nos testes).

Uso em qualquer arquivo de teste:
    from apps.core.tests import *

Isso desabilita a autenticação para todos os testes subsequentes.
"""

from apps.core.permissions import disable_auth_for_tests as _dat

# Desabilita autenticação para testes de view.
# Deve ser importado antes de qualquer teste que acesse views.
_dat()
