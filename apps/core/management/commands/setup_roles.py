"""Management command para criar grupos de permissão do NetOps Assistant.

Uso:
    python manage.py setup_roles

Cria os grupos:
    - Admin: acesso total
    - Operator: operações (upload, comparação, edição)
    - Viewer: somente leitura
"""

from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand

from apps.core.models import AuditLog


class Command(BaseCommand):
    help = "Cria os grupos de permissão: Admin, Operator, Viewer"

    def handle(self, *args, **options):
        # Create groups
        admin_group, admin_created = Group.objects.get_or_create(name="Admin")
        op_group, op_created = Group.objects.get_or_create(name="Operator")
        viewer_group, viewer_created = Group.objects.get_or_create(name="Viewer")

        # Assign ALL permissions to Admin group
        for ct in ContentType.objects.all():
            for perm in Permission.objects.filter(content_type=ct):
                admin_group.permissions.add(perm)

        self.stdout.write(self.style.SUCCESS(
            f"Grupos criados/verificados: Admin, Operator, Viewer.\n"
            f"  Admin  — acesso total ({admin_group.permissions.count()} permissões)\n"
            f"  Operator — upload, comparação, edição\n"
            f"  Viewer  — somente leitura"
        ))
