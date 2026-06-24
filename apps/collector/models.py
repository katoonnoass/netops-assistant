from django.conf import settings
from django.db import models

from apps.devices.models import Device


class NetworkCredential(models.Model):
    class SnmpVersion(models.TextChoices):
        V2C = "v2c", "SNMPv2c"
        V3 = "v3", "SNMPv3"

    name = models.CharField("nome", max_length=100, unique=True)
    username = models.CharField("usuário", max_length=100, blank=True, default="")
    encrypted_password = models.TextField("senha (criptografada)", blank=True, default="")
    encrypted_enable_secret = models.TextField("enable secret (criptografado)", blank=True, default="")
    snmp_community = models.CharField("comunidade SNMP", max_length=100, blank=True, default="")
    snmp_version = models.CharField(
        "versão SNMP", max_length=10, choices=SnmpVersion.choices, default=SnmpVersion.V2C
    )
    vendor_hint = models.CharField(
        "fabricante (opcional)", max_length=20, blank=True, default="",
        help_text="Restringe esta credencial a um fabricante específico",
    )
    priority = models.IntegerField("prioridade", default=0)
    is_active = models.BooleanField("ativo", default=True)
    created_at = models.DateTimeField("criado em", auto_now_add=True)
    updated_at = models.DateTimeField("atualizado em", auto_now=True)

    class Meta:
        verbose_name = "credencial de rede"
        verbose_name_plural = "credenciais de rede"
        ordering = ["-priority", "name"]

    def __str__(self):
        return self.name


class DiscoveryProfile(models.Model):
    name = models.CharField("nome", max_length=100, unique=True)
    description = models.TextField("descrição", blank=True, default="")
    subnets = models.JSONField(
        "sub-redes", blank=True, default=list,
        help_text="Lista de CIDRs: [\"10.0.0.0/24\", \"192.168.0.0/16\"]",
    )
    credential = models.ForeignKey(
        NetworkCredential, on_delete=models.SET_NULL, null=True, blank=True,
        verbose_name="credencial",
    )
    snmp_community = models.CharField(
        "comunidade SNMP (override)", max_length=100, blank=True, default=""
    )
    snmp_version = models.CharField(
        "versão SNMP", max_length=10,
        choices=NetworkCredential.SnmpVersion.choices,
        default=NetworkCredential.SnmpVersion.V2C,
    )
    max_workers = models.PositiveSmallIntegerField("threads simultâneas", default=5)
    timeout = models.PositiveSmallIntegerField("timeout (s)", default=5)
    is_active = models.BooleanField("ativo", default=True)
    created_at = models.DateTimeField("criado em", auto_now_add=True)
    updated_at = models.DateTimeField("atualizado em", auto_now=True)

    class Meta:
        verbose_name = "perfil de descoberta"
        verbose_name_plural = "perfis de descoberta"
        ordering = ["name"]

    def __str__(self):
        return self.name


class CollectorRun(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pendente"
        RUNNING = "running", "Executando"
        SUCCESS = "success", "Sucesso"
        PARTIAL = "partial", "Parcial"
        FAILED = "failed", "Falha"

    profile = models.ForeignKey(
        DiscoveryProfile, on_delete=models.CASCADE, verbose_name="perfil"
    )
    status = models.CharField(
        "status", max_length=20, choices=Status.choices, default=Status.PENDING
    )
    started_at = models.DateTimeField("iniciado em", auto_now_add=True)
    finished_at = models.DateTimeField("finalizado em", null=True, blank=True)
    discovered_count = models.IntegerField("descobertos", default=0)
    collected_count = models.IntegerField("coletados", default=0)
    analyzed_count = models.IntegerField("analisados", default=0)
    failed_count = models.IntegerField("falhas", default=0)
    summary = models.TextField("resumo", blank=True, default="")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        verbose_name="criado por",
    )

    class Meta:
        verbose_name = "execução do coletor"
        verbose_name_plural = "execuções do coletor"
        ordering = ["-started_at"]

    def __str__(self):
        return f"{self.profile.name} - {self.status} ({self.started_at:%Y-%m-%d %H:%M})"


class CollectorTask(models.Model):
    class Action(models.TextChoices):
        SNMP_DISCOVERY = "snmp_discovery", "Descoberta SNMP"
        SSH_COLLECT = "ssh_collect", "Coleta SSH"
        ANALYZE = "analyze", "Análise"

    class Status(models.TextChoices):
        PENDING = "pending", "Pendente"
        RUNNING = "running", "Executando"
        SUCCESS = "success", "Sucesso"
        FAILED = "failed", "Falha"
        SKIPPED = "skipped", "Pulado"

    run = models.ForeignKey(
        CollectorRun, on_delete=models.CASCADE, related_name="tasks",
        verbose_name="execução",
    )
    device = models.ForeignKey(
        Device, on_delete=models.SET_NULL, null=True, blank=True,
        verbose_name="equipamento",
    )
    ip_address = models.GenericIPAddressField("endereço IP", blank=True, null=True)
    action = models.CharField("ação", max_length=20, choices=Action.choices)
    status = models.CharField(
        "status", max_length=20, choices=Status.choices, default=Status.PENDING
    )
    started_at = models.DateTimeField("iniciado em", null=True, blank=True)
    finished_at = models.DateTimeField("finalizado em", null=True, blank=True)
    log = models.TextField("log", blank=True, default="")
    error = models.TextField("erro", blank=True, default="")

    class Meta:
        verbose_name = "tarefa do coletor"
        verbose_name_plural = "tarefas do coletor"
        ordering = ["run", "action", "pk"]

    def __str__(self):
        device_name = self.device.name if self.device else self.ip_address or "?"
        return f"{self.get_action_display()} - {device_name} - {self.status}"
