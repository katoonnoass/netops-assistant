from django.core.management.base import BaseCommand, CommandError

from apps.collector.models import DiscoveryProfile
from apps.collector.services import run_discovery


class Command(BaseCommand):
    help = "Descobre equipamentos via SNMP em sub-redes configuradas"

    def add_arguments(self, parser):
        parser.add_argument("--profile", required=True, help="Nome do perfil de descoberta")
        parser.add_argument("--dry-run", action="store_true", help="Simula sem conectar em equipamentos reais")

    def handle(self, *args, **options):
        profile_name = options["profile"]
        dry_run = options["dry_run"]

        try:
            profile = DiscoveryProfile.objects.get(name=profile_name)
        except DiscoveryProfile.DoesNotExist:
            raise CommandError(f"Perfil '{profile_name}' não encontrado.")

        if not profile.is_active:
            raise CommandError(f"Perfil '{profile_name}' está inativo.")

        self.stdout.write(f"Perfil: {profile.name}")
        self.stdout.write(f"Sub-redes: {', '.join(profile.subnets) if profile.subnets else '(nenhuma)'}")
        self.stdout.write(f"Modo: {'DRY-RUN' if dry_run else 'EXECUÇÃO'}")
        self.stdout.write("")

        if dry_run:
            lines = run_discovery(profile=profile, dry_run=True)
            for line in lines:
                self.stdout.write(line)
            return

        run = run_discovery(profile=profile)

        self.stdout.write(f"Run #{run.pk} finalizada.")
        self.stdout.write(f"  Status: {run.get_status_display()}")
        self.stdout.write(f"  Descobertos: {run.discovered_count}")
        self.stdout.write(f"  Falhas: {run.failed_count}")

        if run.summary:
            self.stdout.write(f"  Resumo: {run.summary}")
