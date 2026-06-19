"""Comando de gerenciamento: analyze_config_file.

Uso:
    python manage.py analyze_config_file <caminho_do_arquivo> \
        --vendor huawei --device-name "NE40-TESTE"

Lê um arquivo de configuração, cria um Device (opcional), cria um
ConfigSnapshot, executa a análise completa e imprime um resumo.
"""

from django.core.management.base import BaseCommand, CommandError

from apps.analysis.models import (
    AnalysisIssue,
    DetectedCircuit,
    DetectedService,
    ParsedConfig,
)
from apps.analysis.services import analyze_config_snapshot
from apps.config_archive.models import ConfigSnapshot
from apps.devices.models import Device


class Command(BaseCommand):
    help = "Analisa um arquivo de configuração e imprime resumo"

    def add_arguments(self, parser):
        parser.add_argument("file_path", type=str, help="Caminho do arquivo de configuração")
        parser.add_argument(
            "--vendor",
            type=str,
            default="huawei",
            help="Vendor do equipamento (padrão: huawei)",
        )
        parser.add_argument(
            "--device-name",
            type=str,
            default="",
            help="Nome do equipamento (criado automaticamente se não existir)",
        )

    def handle(self, *args, **options):
        file_path = options["file_path"]
        vendor = options["vendor"]
        device_name = options["device_name"]

        # Read the config file
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw_config = f.read()
        except FileNotFoundError:
            raise CommandError(f"Arquivo não encontrado: {file_path}")
        except IOError as exc:
            raise CommandError(f"Erro ao ler arquivo: {exc}")

        if not raw_config.strip():
            raise CommandError("O arquivo de configuração está vazio.")

        # Create or find the device
        device = None
        if device_name:
            device, _ = Device.objects.get_or_create(
                name=device_name,
                defaults={"vendor": vendor},
            )
            self.stdout.write(f"Equipamento: {device.name} ({device.vendor})")

        # Create the ConfigSnapshot
        snapshot = ConfigSnapshot.objects.create(
            device=device,
            raw_config=raw_config,
            vendor=vendor,
            source="upload",
            notes=f"Importado de: {file_path}",
        )
        self.stdout.write(f"Snapshot #{snapshot.pk} criado ({len(raw_config)} bytes)")

        # Run analysis
        self.stdout.write("Executando análise...")
        try:
            parsed_config = analyze_config_snapshot(snapshot)
        except (KeyError, ValueError) as exc:
            raise CommandError(str(exc))

        # Count results
        parsed_data = parsed_config.parsed_data
        interface_count = len(parsed_data.get("interfaces", []))
        route_count = len(parsed_data.get("static_routes", []))
        circuit_count = DetectedCircuit.objects.filter(snapshot=snapshot).count()
        issue_count = AnalysisIssue.objects.filter(snapshot=snapshot).count()
        service_count = DetectedService.objects.filter(snapshot=snapshot).count()

        self.stdout.write(self.style.SUCCESS("\n=== RESUMO DA ANÁLISE ==="))
        self.stdout.write(f"  ParsedConfig #:           {parsed_config.pk}")
        self.stdout.write(f"  Interfaces detectadas:    {interface_count}")
        self.stdout.write(f"  Rotas estáticas:          {route_count}")
        self.stdout.write(f"  Circuitos detectados:     {circuit_count}")
        self.stdout.write(f"  Serviços detectados:      {service_count}")
        self.stdout.write(f"  Issues encontradas:       {issue_count}")

        # Show issues
        if issue_count > 0:
            self.stdout.write("\n--- Issues ---")
            for issue in AnalysisIssue.objects.filter(snapshot=snapshot):
                msg = f"  [{issue.get_severity_display()}/{issue.code}] {issue.title}"
                if issue.severity == "critical":
                    self.stdout.write(self.style.ERROR(msg))
                elif issue.severity == "warning":
                    self.stdout.write(self.style.WARNING(msg))
                else:
                    self.stdout.write(msg)

        # Show circuits
        if circuit_count > 0:
            self.stdout.write("\n--- Circuitos ---")
            for circuit in DetectedCircuit.objects.filter(snapshot=snapshot):
                det = circuit.details
                self.stdout.write(
                    f"  [{circuit.get_circuit_type_display()}] "
                    f"{det.get('interface', '?')} "
                    f"(local: {det.get('local_ip', '?')} -> "
                    f"remote: {det.get('remote_ip', '?')})"
                )
                if det.get("routed_prefix"):
                    self.stdout.write(
                        f"    Prefixo roteado: {det['routed_prefix']}"
                    )

        # Show services
        if service_count > 0:
            self.stdout.write("\n--- Serviços ---")
            for svc in DetectedService.objects.filter(snapshot=snapshot):
                self.stdout.write(
                    f"  [{svc.get_service_type_display()}] "
                    f"{svc.name} "
                    f"(confiança: {svc.confidence:.0%})"
                )
