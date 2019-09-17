from django.core.management.base import BaseCommand, CommandError
from directory.models import CipherSuite


class Command(BaseCommand):
    help = 'Updates security ratings of stores cipher suites'

    def handle(self, *args, **options):
        """Main function to be run when command is executed."""

        recommended = secure = insecure = weak = 0

        for cs in CipherSuite.objects.all():
            if cs in CipherSuite.custom_filters.recommended():
                recommended += CipherSuite.objects.filter(name=cs.name).update(security = 0)
            elif cs in CipherSuite.custom_filters.secure():
                secure += CipherSuite.objects.filter(name=cs.name).update(security = 1)
            elif cs in CipherSuite.custom_filters.weak():
                weak += CipherSuite.objects.filter(name=cs.name).update(security = 2)
            elif cs in CipherSuite.custom_filters.insecure():
                insecure += CipherSuite.objects.filter(name=cs.name).update(security = 3)

        updates = recommended + secure + insecure + weak

        self.stdout.write(
            self.style.SUCCESS(
                f"Successfully updated {updates} cipher suite ratings:\n" +
                f"- {recommended} rated 'recommended'\n" +
                f"- {secure} rated 'secure'\n" +
                f"- {weak} rated 'weak'\n" +
                f"- {insecure} rated 'insecure'"
            )
        )
