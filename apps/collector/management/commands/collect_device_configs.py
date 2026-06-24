from django.core.management.base import BaseCommand, CommandError

from apps.collector.models import DiscoveryProfile
from apps.collector.services import run_collection
from apps.devices.models import Device


class Command(BaseCommand):
    help = "Coleta configuração de equipamentos via SSH"

    def add_arguments(self, parser):
        parser.add_argument("--profile", help="Nome do perfil (coleta todos os devices ativos)")
        parser.add_argument("--device", help="Nome do equipamento específico")
        parser.add_argument("--analyze", action="store_true", help="Executa análise após coleta")
        parser.add_argument("--dry-run", action="store_true", help="Simula sem conectar em equipamentos reais")

    def handle(self, *args, **options):
        profile_name = options.get("profile")
        device_name = options.get("device")
        analyze = options.get("analyze", False)
        dry_run = options.get("dry_run", False)

        if not profile_name and not device_name:
            raise CommandError("Informe --profile ou --device.")

        profile = None
        device = None

        if profile_name:
            try:
                profile = DiscoveryProfile.objects.get(name=profile_name)
            except DiscoveryProfile.DoesNotExist:
                raise CommandError(f"Perfil '{profile_name}' não encontrado.")

        if device_name:
            try:
                device = Device.objects.get(name=device_name)
            except Device.DoesNotExist:
                raise CommandError(f"Equipamento '{device_name}' não encontrado.")

        if dry_run:
            self.stdout.write("[DRY-RUN] Coleta SSH")
            if profile:
                self.stdout.write(f"  Perfil: {profile.name}")
                devices = Device.objects.filter(collector_enabled=True)
                self.stdout.write(f"  Dispositivos alvo: {devices.count()}")
            if device:
                self.stdout.write(f"  Dispositivo: {device.name} ({device.ip_address})")
            self.stdout.write(f"  Analisar após coleta: {'Sim' if analyze else 'Não'}")
            self.stdout.write("  Nenhuma conexão real será realizada.")
            return

        if device and not device.collector_enabled:
            self.stdout.write(self.style.WARNING(f"Coleta desabilitada para {device.name}."))
            return

        try:
            run = run_collection(profile=profile, device=device, analyze=analyze)
        except ValueError as e:
            raise CommandError(str(e)) from None

        self.stdout.write(f"Run #{run.pk} finalizada.")
        self.stdout.write(f"  Status: {run.get_status_display()}")
        self.stdout.write(f"  Coletados: {run.collected_count}")
        self.stdout.write(f"  Analisados: {run.analyzed_count}")
        self.stdout.write(f"  Falhas: {run.failed_count}")
        if run.summary:
            self.stdout.write(f"  Resumo: {run.summary}")
