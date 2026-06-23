"""Helpers de permissão para o NetOps Assistant.

Grupos:
    Admin   — acesso total.
    Operator — operações (upload, comparar, editar dispositivos).
    Viewer   — somente leitura (dashboard, listas, análises, documentação).

Uso:
    from apps.core.permissions import require_role, is_admin, is_operator, is_viewer
"""

from django.conf import settings
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.models import Group
from django.shortcuts import render


# ── Grupo constants ──────────────────────────────────────────────────

GROUP_ADMIN = "Admin"
GROUP_OPERATOR = "Operator"
GROUP_VIEWER = "Viewer"

ALL_GROUPS = [GROUP_ADMIN, GROUP_OPERATOR, GROUP_VIEWER]

# ── Test override flag ───────────────────────────────────────────────

_AUTH_DISABLED = False


def disable_auth_for_tests():
    """Desabilita todos os decorators de autenticação (usado em testes)."""
    global _AUTH_DISABLED
    _AUTH_DISABLED = True


def enable_auth_for_tests():
    """Reabilita os decorators de autenticação."""
    global _AUTH_DISABLED
    _AUTH_DISABLED = False


# ── Functions ────────────────────────────────────────────────────────


def setup_roles():
    """Cria os grupos de permissão no banco."""
    for name in ALL_GROUPS:
        Group.objects.get_or_create(name=name)


def user_in_group(user, group_name: str) -> bool:
    """Verifica se o usuário pertence a um grupo."""
    if not user.is_authenticated:
        return False
    if user.is_superuser:
        return True
    return user.groups.filter(name=group_name).exists()


def is_admin(user) -> bool:
    """Admin ou superuser."""
    return user.is_authenticated and (user.is_superuser or user_in_group(user, GROUP_ADMIN))


def is_operator(user) -> bool:
    """Operator ou superior."""
    return is_admin(user) or user_in_group(user, GROUP_OPERATOR)


def is_viewer(user) -> bool:
    """Qualquer usuário autenticado (Viewer é o nível mínimo de acesso)."""
    return bool(user.is_authenticated)


# ── Decorators ───────────────────────────────────────────────────────


def _maybe_wrap(view_func, test_func, login_url):
    """Aplica o decorator de permissão, ou retorna a view original se auth desabilitado."""
    if _AUTH_DISABLED:
        return view_func
    return user_passes_test(test_func, login_url=login_url)(view_func)


def admin_required(view_func):
    """Decorator: somente Admin ou superuser."""
    return _maybe_wrap(view_func, is_admin, "/accounts/login/")


def operator_required(view_func):
    """Decorator: Operator, Admin ou superuser."""
    return _maybe_wrap(view_func, is_operator, "/accounts/login/")


def viewer_required(view_func):
    """Decorator: qualquer usuário autenticado."""
    return _maybe_wrap(view_func, is_viewer, "/accounts/login/")


def permission_denied_view(request, exception=None):
    """View para 403 — acesso negado."""
    return render(request, "core/permission_denied.html", status=403)
