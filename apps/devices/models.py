from django.db import models


class Device(models.Model):
    class Vendor(models.TextChoices):
        HUAWEI = "huawei", "Huawei"
        ZTE = "zte", "ZTE"
        DATACOM = "datacom", "Datacom"
        CISCO = "cisco", "Cisco"
        MIKROTIK = "mikrotik", "MikroTik"
        OTHER = "other", "Outro"

    class Role(models.TextChoices):
        CORE = "core", "Core"
        DISTRIBUTION = "distribution", "Distribuição"
        ACCESS = "access", "Acesso"
        BORDER = "border", "Borda"
        PE = "pe", "PE"
        P = "p", "P"
        ROUTER = "router", "Roteador"
        SWITCH = "switch", "Switch"
        FIREWALL = "firewall", "Firewall"
        BNG = "bng", "BNG"
        OTHER = "other", "Outro"

    name = models.CharField("nome", max_length=100, unique=True)
    vendor = models.CharField(
        "fabricante",
        max_length=20,
        choices=Vendor.choices,
        default=Vendor.HUAWEI,
    )
    platform = models.CharField("plataforma", max_length=100, blank=True, default="")
    role = models.CharField(
        "função",
        max_length=30,
        choices=Role.choices,
        blank=True,
        default="",
    )
    site = models.CharField("site", max_length=100, blank=True, default="")
    ip_address = models.GenericIPAddressField("endereço IP", blank=True, null=True)
    hostname = models.CharField(max_length=255, blank=True, default="")
    description = models.TextField("descrição", blank=True, default="")
    created_at = models.DateTimeField("criado em", auto_now_add=True)
    updated_at = models.DateTimeField("atualizado em", auto_now=True)

    class Meta:
        verbose_name = "equipamento"
        verbose_name_plural = "equipamentos"
        ordering = ["name"]

    def __str__(self):
        return self.name
