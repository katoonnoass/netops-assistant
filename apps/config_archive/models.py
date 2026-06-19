from django.db import models

from apps.devices.models import Device


class ConfigSnapshot(models.Model):
    device = models.ForeignKey(
        Device,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name="equipamento",
        related_name="snapshots",
    )
    raw_config = models.TextField("configuração bruta")
    vendor = models.CharField(
        "fabricante",
        max_length=20,
        blank=True,
        default="",
        help_text="Detectado automaticamente ou informado pelo usuário",
    )
    source = models.CharField(
        "origem",
        max_length=20,
        choices=[
            ("paste", "Colado"),
            ("upload", "Upload de arquivo"),
            ("api", "API"),
        ],
        default="paste",
    )
    notes = models.TextField("observações", blank=True, default="")
    created_at = models.DateTimeField("criado em", auto_now_add=True)

    class Meta:
        verbose_name = "snapshot de configuração"
        verbose_name_plural = "snapshots de configuração"
        ordering = ["-created_at"]

    def __str__(self):
        device_name = self.device.name if self.device else "(sem equipamento)"
        return f"{device_name} - {self.created_at:%Y-%m-%d %H:%M}"
