"""Modelos do app Core — AuditLog e helpers."""

from django.conf import settings
from django.db import models


class AuditLog(models.Model):
    """Registro de auditoria para ações operacionais."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name="usuário",
    )
    action = models.CharField("ação", max_length=50, db_index=True)
    object_type = models.CharField("tipo de objeto", max_length=50, blank=True, default="")
    object_id = models.CharField("ID do objeto", max_length=50, blank=True, default="")
    description = models.TextField("descrição", blank=True, default="")
    ip_address = models.GenericIPAddressField("endereço IP", blank=True, null=True)
    user_agent = models.TextField("user-agent", blank=True, default="")
    metadata = models.JSONField("metadados", blank=True, default=dict)
    created_at = models.DateTimeField("criado em", auto_now_add=True, db_index=True)

    class Meta:
        verbose_name = "log de auditoria"
        verbose_name_plural = "logs de auditoria"
        ordering = ["-created_at"]

    def __str__(self):
        user_str = self.user.get_username() if self.user else "anônimo"
        return f"[{self.created_at:%Y-%m-%d %H:%M}] {user_str} — {self.action}"
