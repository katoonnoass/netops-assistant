"""Comando de gerenciamento: analyze_snapshot.

Uso:
    python manage.py analyze_snapshot <snapshot_id>

Executa a análise completa de um ConfigSnapshot existente.
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


class Command(BaseCommand):
    help = "Analisa um ConfigSnapshot existente e gera circuitos/issues"

    def add_arguments(self, parser):
        parser.add_argument(
            "snapshot_id",
            type=int,
            help="ID do ConfigSnapshot a ser analisado",
        )

    def handle(self, *args, **options):
        snapshot_id = options["snapshot_id"]

        try:
            snapshot = ConfigSnapshot.objects.get(pk=snapshot_id)
        except ConfigSnapshot.DoesNotExist:
            raise CommandError(f"ConfigSnapshot com ID {snapshot_id} não encontrado.")

        self.stdout.write(f"Analisando snapshot #{snapshot_id}...")

        try:
            parsed_config = analyze_config_snapshot(snapshot)
        except (KeyError, ValueError) as exc:
            raise CommandError(str(exc))

        # Count results
        circuit_count = DetectedCircuit.objects.filter(snapshot=snapshot).count()
        issue_count = AnalysisIssue.objects.filter(snapshot=snapshot).count()
        service_count = DetectedService.objects.filter(snapshot=snapshot).count()

        self.stdout.write(self.style.SUCCESS("Análise concluída!"))
        self.stdout.write(f"  ParsedConfig #{parsed_config.pk} criado")
        self.stdout.write(f"  Circuitos detectados: {circuit_count}")
        self.stdout.write(f"  Serviços detectados:  {service_count}")
        self.stdout.write(f"  Issues encontradas:   {issue_count}")

        # Show issues summary
        if issue_count > 0:
            self.stdout.write("\nIssues:")
            for issue in AnalysisIssue.objects.filter(snapshot=snapshot):
                msg = f"  [{issue.get_severity_display()}] {issue.title}"
                if issue.severity == "critical":
                    self.stdout.write(self.style.ERROR(msg))
                elif issue.severity == "warning":
                    self.stdout.write(self.style.WARNING(msg))
                else:
                    self.stdout.write(msg)

        # Show circuits summary
        if circuit_count > 0:
            self.stdout.write("\nCircuitos:")
            for circuit in DetectedCircuit.objects.filter(snapshot=snapshot):
                det = circuit.details
                self.stdout.write(
                    f"  [{circuit.get_circuit_type_display()}] "
                    f"{det.get('interface', '?')} -> "
                    f"{det.get('remote_ip', '?')} "
                    f"(rede: {det.get('transit_network', '?')})"
                )
