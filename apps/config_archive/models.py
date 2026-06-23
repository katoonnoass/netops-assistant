import hashlib

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
    name = models.CharField("nome", max_length=255, blank=True, default="")
    raw_config = models.TextField("configuração bruta")
    config_hash = models.CharField(
        "hash SHA256",
        max_length=64,
        blank=True,
        default="",
        editable=False,
        db_index=True,
        help_text="SHA256 do conteúdo normalizado, usado para deduplicação",
    )
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
    captured_at = models.DateTimeField(
        "capturado em", blank=True, null=True, help_text="Data/hora da captura no equipamento"
    )
    is_baseline = models.BooleanField("baseline", default=False)
    notes = models.TextField("observações", blank=True, default="")
    description = models.TextField("descrição", blank=True, default="")
    created_at = models.DateTimeField("criado em", auto_now_add=True)

    class Meta:
        verbose_name = "snapshot de configuração"
        verbose_name_plural = "snapshots de configuração"
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        if self.raw_config:
            normalized = self.raw_config.strip().replace("\r\n", "\n").replace("\r", "\n")
            self.config_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        super().save(*args, **kwargs)

    def is_duplicate_of(self) -> "ConfigSnapshot | None":
        """Retorna o snapshot original se este for duplicado (mesmo device + mesmo hash)."""
        if not self.device_id:
            return None
        # Compute hash if not yet computed (e.g., before save)
        config_hash = self.config_hash
        if not config_hash and self.raw_config:
            normalized = self.raw_config.strip().replace("\r\n", "\n").replace("\r", "\n")
            config_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        if not config_hash:
            return None
        qs = ConfigSnapshot.objects.filter(
            device=self.device,
            config_hash=config_hash,
        )
        if self.pk:
            qs = qs.exclude(pk=self.pk)
        return qs.first()

    @property
    def hash_short(self) -> str:
        """Retorna os primeiros 12 caracteres do hash para exibição."""
        return self.config_hash[:12] if self.config_hash else ""

    def __str__(self):
        device_name = self.device.name if self.device else "(sem equipamento)"
        label = f" {self.name}" if self.name else ""
        return f"{device_name}{label} - {self.created_at:%Y-%m-%d %H:%M}"
