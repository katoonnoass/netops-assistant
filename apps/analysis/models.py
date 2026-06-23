from django.db import models

from apps.config_archive.models import ConfigSnapshot


class ParsedConfig(models.Model):
    snapshot = models.ForeignKey(
        ConfigSnapshot,
        on_delete=models.CASCADE,
        verbose_name="snapshot",
        related_name="parsed_configs",
    )
    parsed_data = models.JSONField("dados parseados")
    parser_version = models.CharField("versão do parser", max_length=20, default="1.0")
    created_at = models.DateTimeField("criado em", auto_now_add=True)

    class Meta:
        verbose_name = "configuração parseada"
        verbose_name_plural = "configurações parseadas"
        ordering = ["-created_at"]

    def __str__(self):
        return f"Parsed #{self.pk} - {self.snapshot}"


class DetectedCircuit(models.Model):
    class CircuitType(models.TextChoices):
        L3 = "l3", "Circuito L3"
        L3_TRANSIT = "l3_transit", "Trânsito L3"
        VLAN_TRANSPORT = "vlan_transport", "VLAN de Transporte"
        QINQ = "qinq", "QinQ"
        QINQ_TRANSPORT = "qinq_transport", "Transporte QinQ"
        BGP = "bgp", "BGP com Cliente"
        TRANSPORT_MIKROTIK = "transport_mikrotik", "Transporte MikroTik"
        OLT = "olt", "Circuito de OLT"
        BNG = "bng", "BNG/BAS"
        L2VPN = "l2vpn", "L2VPN/VSI/VPLS"
        L2VPN_VSI = "l2vpn_vsi", "L2VPN com VSI"
        OTHER = "other", "Outro"

    snapshot = models.ForeignKey(
        ConfigSnapshot,
        on_delete=models.CASCADE,
        verbose_name="snapshot",
        related_name="detected_circuits",
    )
    circuit_type = models.CharField(
        "tipo de circuito",
        max_length=30,
        choices=CircuitType.choices,
    )
    description = models.TextField("descrição", blank=True, default="")
    details = models.JSONField("detalhes", blank=True, default=dict)
    created_at = models.DateTimeField("criado em", auto_now_add=True)

    class Meta:
        verbose_name = "circuito detectado"
        verbose_name_plural = "circuitos detectados"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.get_circuit_type_display()} - {self.snapshot}"


class DetectedService(models.Model):
    class ServiceType(models.TextChoices):
        BNG = "bng", "BNG/BAS"
        AAA = "aaa", "Autenticação AAA"
        RADIUS = "radius", "Servidor RADIUS"
        IP_POOL = "ip_pool", "Pool de Endereços IP"
        SUBSCRIBER_ACCESS = "subscriber_access", "Acesso de Assinante"
        SNMP = "snmp", "SNMP"
        NTP = "ntp", "NTP"
        SYSLOG = "syslog", "Syslog"
        MANAGEMENT_ACCESS = "management_access", "Acesso Administrativo"
        LOCAL_USER = "local_user", "Usuário Local"
        L2_SWITCHING = "l2_switching", "Comutação L2"
        VLAN_SERVICE = "vlan_service", "VLAN"
        STP = "stp", "STP/RSTP/MSTP"
        OSPF = "ospf", "OSPF"
        ISIS = "isis", "ISIS"
        MPLS = "mpls", "MPLS"
        MPLS_LDP = "mpls_ldp", "MPLS LDP"
        VRF = "vrf", "VRF/VPN-instance"
        L3VPN = "l3vpn", "L3VPN MPLS"
        VPNV4 = "vpnv4", "BGP VPNv4"
        QOS = "qos", "QoS / Qualidade de Serviço"
        TRAFFIC_POLICY = "traffic_policy", "Traffic Policy"
        QOS_CAR = "qos_car", "CAR / Controle de Banda"
        NAT = "nat", "NAT / PAT"
        NAT_OUTBOUND = "nat_outbound", "NAT Outbound (PAT)"
        NAT_STATIC = "nat_static", "NAT Estático"
        NAT_SERVER = "nat_server", "NAT Server / Port Forward"
        IPV6 = "ipv6", "IPv6"
        BGP_IPV6 = "bgp_ipv6", "BGP IPv6 Unicast"
        VPNV6 = "vpnv6", "BGP VPNv6"
        OSPFV3 = "ospfv3", "OSPFv3"
        ISIS_IPV6 = "isis_ipv6", "ISIS IPv6"
        BNG_ADVANCED = "bng_advanced", "BNG Avançado"
        BAS_INTERFACE = "bas_interface", "BAS Interface"
        SUBSCRIBER_DOMAIN = "subscriber_domain", "Domínio de Assinante"
        AAA_SCHEME = "aaa_scheme", "AAA Scheme"
        RADIUS_GROUP = "radius_group", "Grupo RADIUS"
        PPPOE = "pppoe", "PPPoE Server"
        VIRTUAL_TEMPLATE = "virtual_template", "Virtual-Template"
        PPP_ACCESS = "ppp_access", "PPP Subscriber Access"
        BFD = "bfd", "BFD / Fast Convergence"
        GRACEFUL_RESTART = "graceful_restart", "Graceful Restart"
        NSR = "nsr", "NSR / Non-Stop Routing"
        MULTICAST = "multicast", "Multicast Routing"
        PIM = "pim", "PIM Sparse Mode"
        IGMP = "igmp", "IGMP / IPTV Access"
        IGMP_SNOOPING = "igmp_snooping", "IGMP Snooping"
        MLD = "mld", "MLD IPv6 Multicast"
        GPON_OLT = "gpon_olt", "GPON / OLT"
        EVPN_VXLAN = "evpn_vxlan", "EVPN / VXLAN"
        SEGMENT_ROUTING = "segment_routing", "Segment Routing / SRv6"
        MPLS_TE = "mpls_te", "MPLS-TE / RSVP-TE"
        CGNAT = "cgnat", "CGNAT Avançado"
        MSDP = "msdp", "MSDP"
        TELEMETRY = "telemetry", "Telemetria / Streaming"

    snapshot = models.ForeignKey(
        ConfigSnapshot,
        on_delete=models.CASCADE,
        verbose_name="snapshot",
        related_name="detected_services",
    )
    service_type = models.CharField(
        "tipo de serviço",
        max_length=30,
        choices=ServiceType.choices,
    )
    name = models.CharField(
        "nome", max_length=200, blank=True, default=""
    )
    description = models.TextField("descrição", blank=True, default="")
    confidence = models.FloatField("confiança", default=0.0)
    metadata = models.JSONField("metadados", blank=True, default=dict)
    created_at = models.DateTimeField("criado em", auto_now_add=True)

    class Meta:
        verbose_name = "serviço detectado"
        verbose_name_plural = "serviços detectados"
        ordering = ["-confidence", "-created_at"]

    def __str__(self):
        name_part = f" - {self.name}" if self.name else ""
        return f"[{self.get_service_type_display()}]{name_part}"


class ConfigComparison(models.Model):
    base_snapshot = models.ForeignKey(
        ConfigSnapshot,
        on_delete=models.CASCADE,
        verbose_name="snapshot base",
        related_name="comparisons_as_base",
    )
    target_snapshot = models.ForeignKey(
        ConfigSnapshot,
        on_delete=models.CASCADE,
        verbose_name="snapshot alvo",
        related_name="comparisons_as_target",
    )
    title = models.CharField("título", max_length=255, blank=True, default="")
    summary = models.TextField("resumo", blank=True, default="")
    diff_data = models.JSONField("dados da comparação", blank=True, default=dict)
    created_at = models.DateTimeField("criado em", auto_now_add=True)

    class Meta:
        verbose_name = "comparação de configurações"
        verbose_name_plural = "comparações de configurações"
        ordering = ["-created_at"]

    def __str__(self):
        return f"Comparação #{self.pk} - {self.base_snapshot} vs {self.target_snapshot}"


class AnalysisIssue(models.Model):
    class Severity(models.TextChoices):
        INFO = "info", "Informativo"
        WARNING = "warning", "Atenção"
        CRITICAL = "critical", "Crítico"

    snapshot = models.ForeignKey(
        ConfigSnapshot,
        on_delete=models.CASCADE,
        verbose_name="snapshot",
        related_name="analysis_issues",
    )
    severity = models.CharField(
        "severidade",
        max_length=10,
        choices=Severity.choices,
        default=Severity.INFO,
    )
    category = models.CharField("categoria", max_length=50, blank=True, default="")
    code = models.CharField("código", max_length=60, blank=True, default="")
    title = models.CharField("título", max_length=200)
    description = models.TextField("descrição", blank=True, default="")
    metadata = models.JSONField("metadados", blank=True, default=dict)
    created_at = models.DateTimeField("criado em", auto_now_add=True)

    class Meta:
        verbose_name = "análise/issue"
        verbose_name_plural = "análises/issues"
        ordering = ["-severity", "-created_at"]

    def __str__(self):
        return f"[{self.get_severity_display()}] {self.title}"
