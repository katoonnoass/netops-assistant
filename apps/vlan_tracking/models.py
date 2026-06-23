from django.db import models


class VlanTrackSession(models.Model):
    name = models.CharField(max_length=200, verbose_name="Nome")
    description = models.TextField(blank=True, verbose_name="Descrição")
    created_by = models.ForeignKey(
        "auth.User", on_delete=models.SET_NULL, null=True, blank=True, verbose_name="Criado por"
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Criado em")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Atualizado em")

    class Meta:
        verbose_name = "Sessão de rastreamento"
        verbose_name_plural = "Sessões de rastreamento"
        ordering = ["-created_at"]

    def __str__(self):
        return self.name


class VlanTrackDevice(models.Model):
    ROLE_HINTS = [
        ("core", "Core"),
        ("distribution", "Distribuição"),
        ("access", "Acesso"),
        ("pe", "PE"),
        ("p", "P"),
        ("bng", "BNG"),
        ("unknown", "Desconhecido"),
    ]

    session = models.ForeignKey(
        VlanTrackSession, on_delete=models.CASCADE, related_name="track_devices"
    )
    device = models.ForeignKey(
        "devices.Device", on_delete=models.CASCADE, related_name="vlan_track_entries"
    )
    snapshot = models.ForeignKey(
        "config_archive.ConfigSnapshot", on_delete=models.SET_NULL, null=True, blank=True
    )
    parsed_config = models.ForeignKey(
        "analysis.ParsedConfig", on_delete=models.SET_NULL, null=True, blank=True
    )
    order = models.IntegerField(default=0, verbose_name="Ordem")
    role_hint = models.CharField(
        max_length=20, choices=ROLE_HINTS, default="unknown", verbose_name="Função sugerida"
    )

    class Meta:
        verbose_name = "Dispositivo na sessão"
        verbose_name_plural = "Dispositivos na sessão"
        ordering = ["session", "order"]
        constraints = [
            models.UniqueConstraint(
                fields=["session", "device", "snapshot"],
                name="uq_vlan_track_device_per_session",
            )
        ]

    def __str__(self):
        return f"{self.device.name} [{self.role_hint}]"


class DeviceLink(models.Model):
    DISCOVERY_METHODS = [
        ("manual", "Manual"),
        ("subnet", "Subrede"),
        ("description", "Descrição"),
    ]
    CONFIDENCE_LEVELS = [
        ("high", "Alta"),
        ("medium", "Média"),
        ("low", "Baixa"),
    ]
    LINK_STATUSES = [
        ("discovered", "Descoberto"),
        ("confirmed", "Confirmado"),
        ("ignored", "Ignorado"),
    ]

    session = models.ForeignKey(
        VlanTrackSession, on_delete=models.CASCADE, related_name="links"
    )
    device_a = models.ForeignKey(
        "devices.Device", on_delete=models.CASCADE, related_name="links_as_a"
    )
    interface_a = models.CharField(max_length=200, verbose_name="Interface A")
    device_b = models.ForeignKey(
        "devices.Device", on_delete=models.CASCADE, related_name="links_as_b"
    )
    interface_b = models.CharField(max_length=200, verbose_name="Interface B")
    discovery_method = models.CharField(
        max_length=20, choices=DISCOVERY_METHODS, default="manual"
    )
    confidence = models.CharField(
        max_length=10, choices=CONFIDENCE_LEVELS, default="medium"
    )
    status = models.CharField(
        max_length=20, choices=LINK_STATUSES, default="discovered"
    )
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Enlace entre dispositivos"
        verbose_name_plural = "Enlaces entre dispositivos"
        constraints = [
            models.UniqueConstraint(
                fields=["session", "device_a", "interface_a", "device_b", "interface_b"],
                name="uq_device_link_unique",
            )
        ]

    def __str__(self):
        return f"{self.device_a}:{self.interface_a} ↔ {self.device_b}:{self.interface_b} ({self.discovery_method})"


class VlanDefinition(models.Model):
    session = models.ForeignKey(
        VlanTrackSession, on_delete=models.CASCADE, related_name="vlan_definitions"
    )
    vlan_id = models.IntegerField(verbose_name="VLAN ID")
    name = models.CharField(max_length=200, blank=True, verbose_name="Nome")
    description = models.TextField(blank=True, verbose_name="Descrição")
    first_seen_device = models.ForeignKey(
        "devices.Device", on_delete=models.SET_NULL, null=True, blank=True
    )
    device_count = models.IntegerField(default=0, verbose_name="Dispositivos")
    interface_count = models.IntegerField(default=0, verbose_name="Interfaces")

    class Meta:
        verbose_name = "Definição de VLAN"
        verbose_name_plural = "Definições de VLAN"
        ordering = ["session", "vlan_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["session", "vlan_id"], name="uq_vlan_definition_per_session"
            )
        ]

    def __str__(self):
        return f"VLAN {self.vlan_id} - {self.name or '(sem nome)'}"


class VlanInterface(models.Model):
    PORT_MODES = [
        ("access", "Access"),
        ("trunk", "Trunk"),
        ("hybrid", "Hybrid"),
        ("subinterface", "Subinterface"),
        ("qinq", "QinQ"),
        ("l2vpn", "L2VPN"),
        ("bas", "BAS"),
        ("unknown", "Desconhecido"),
    ]
    SOURCE_TYPES = [
        ("access_vlan", "Access VLAN"),
        ("trunk_allowed", "Trunk allowed"),
        ("hybrid_tagged", "Hybrid tagged"),
        ("hybrid_untagged", "Hybrid untagged"),
        ("dot1q", "Subinterface dot1q"),
        ("qinq", "QinQ"),
        ("vsi", "L2VPN VSI"),
        ("bas_user_vlan", "BAS user-vlan"),
    ]

    session = models.ForeignKey(
        VlanTrackSession, on_delete=models.CASCADE, related_name="vlan_interfaces"
    )
    device = models.ForeignKey("devices.Device", on_delete=models.CASCADE)
    snapshot = models.ForeignKey(
        "config_archive.ConfigSnapshot", on_delete=models.SET_NULL, null=True, blank=True
    )
    interface_name = models.CharField(max_length=200, verbose_name="Interface")
    vlan_id = models.IntegerField(verbose_name="VLAN ID")
    port_mode = models.CharField(
        max_length=20, choices=PORT_MODES, default="unknown", verbose_name="Modo"
    )
    tagged = models.BooleanField(default=True, verbose_name="Tagged")
    pvid = models.BooleanField(default=False, verbose_name="PVID")
    source = models.CharField(
        max_length=20, choices=SOURCE_TYPES, default="access_vlan"
    )
    description = models.TextField(blank=True)
    raw_metadata = models.JSONField(null=True, blank=True)

    class Meta:
        verbose_name = "Interface VLAN"
        verbose_name_plural = "Interfaces VLAN"
        indexes = [
            models.Index(fields=["session", "vlan_id"]),
            models.Index(fields=["session", "device"]),
        ]

    def __str__(self):
        tag = "T" if self.tagged else "U"
        return f"{self.device.name}:{self.interface_name} VLAN {self.vlan_id} ({tag})"


class VlanEndpoint(models.Model):
    ENDPOINT_TYPES = [
        ("access", "Porta Access"),
        ("subinterface_l3", "Subinterface L3"),
        ("l2vpn_vsi", "L2VPN VSI"),
        ("bas", "BAS/BNG"),
        ("qinq_edge", "QinQ Edge"),
        ("unknown", "Desconhecido"),
    ]

    session = models.ForeignKey(
        VlanTrackSession, on_delete=models.CASCADE, related_name="vlan_endpoints"
    )
    vlan_definition = models.ForeignKey(
        VlanDefinition, on_delete=models.CASCADE, related_name="endpoints"
    )
    device = models.ForeignKey("devices.Device", on_delete=models.CASCADE)
    interface_name = models.CharField(max_length=200, verbose_name="Interface")
    endpoint_type = models.CharField(
        max_length=20, choices=ENDPOINT_TYPES, default="unknown"
    )
    description = models.TextField(blank=True)
    metadata = models.JSONField(null=True, blank=True)

    class Meta:
        verbose_name = "Ponto terminal de VLAN"
        verbose_name_plural = "Pontos terminais de VLAN"

    def __str__(self):
        return f"{self.device.name}:{self.interface_name} ({self.get_endpoint_type_display()})"


class VlanPath(models.Model):
    PATH_STATUSES = [
        ("active", "Ativo"),
        ("partial", "Parcial"),
        ("suspected", "Suspeito"),
    ]

    session = models.ForeignKey(
        VlanTrackSession, on_delete=models.CASCADE, related_name="vlan_paths"
    )
    vlan_definition = models.ForeignKey(
        VlanDefinition, on_delete=models.CASCADE, related_name="paths"
    )
    from_device = models.ForeignKey(
        "devices.Device", on_delete=models.CASCADE, related_name="vlan_paths_from"
    )
    from_interface = models.CharField(max_length=200)
    to_device = models.ForeignKey(
        "devices.Device", on_delete=models.CASCADE, related_name="vlan_paths_to"
    )
    to_interface = models.CharField(max_length=200)
    via_link = models.ForeignKey(
        DeviceLink, on_delete=models.SET_NULL, null=True, blank=True
    )
    tagged = models.BooleanField(default=True)
    status = models.CharField(
        max_length=20, choices=PATH_STATUSES, default="active"
    )
    metadata = models.JSONField(null=True, blank=True)

    class Meta:
        verbose_name = "Caminho de VLAN"
        verbose_name_plural = "Caminhos de VLAN"

    def __str__(self):
        return f"VLAN {self.vlan_definition.vlan_id}: {self.from_device}:{self.from_interface} → {self.to_device}:{self.to_interface}"


class VlanTrackingIssue(models.Model):
    SEVERITIES = [
        ("critical", "Crítico"),
        ("high", "Alto"),
        ("medium", "Médio"),
        ("low", "Baixo"),
        ("info", "Informativo"),
    ]

    session = models.ForeignKey(
        VlanTrackSession, on_delete=models.CASCADE, related_name="tracking_issues"
    )
    vlan_definition = models.ForeignKey(
        VlanDefinition, on_delete=models.SET_NULL, null=True, blank=True
    )
    device = models.ForeignKey(
        "devices.Device", on_delete=models.SET_NULL, null=True, blank=True
    )
    interface_name = models.CharField(max_length=200, blank=True)
    severity = models.CharField(
        max_length=10, choices=SEVERITIES, default="medium"
    )
    code = models.CharField(max_length=100, db_index=True)
    title = models.CharField(max_length=300)
    description = models.TextField(blank=True)
    metadata = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Issue de rastreamento"
        verbose_name_plural = "Issues de rastreamento"
        ordering = ["-severity", "code"]

    def __str__(self):
        return f"[{self.get_severity_display()}] {self.code}: {self.title}"
