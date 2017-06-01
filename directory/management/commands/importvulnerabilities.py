from django.core.management.base import BaseCommand, CommandError
from directory.models import Vulnerability, CipherSuite

from os.path import abspath
import re

class Command(BaseCommand):
    help = 'Imports data from a csv file including information on common vulnerabilities.'

    def add_vulnerability(self, attribute, value, vname):
        """Adds vulnerability with <vname> to all cipher suites
        that contain a certain <value> in a given <attribute>"""

        vuln = Vulnerability.objects.get(name=vname)
        if attribute == 'protocol_version':
            for c in CipherSuite.objects.filter(protocol_version=value):
                c.protocol_version.vulnerabilities.add(vuln)
        elif attribute == 'kex_algorithm':
            for c in CipherSuite.objects.filter(kex_algorithm=value):
                c.kex_algorithm.vulnerabilities.add(vuln)
        elif attribute == 'auth_algorithm':
            for c in CipherSuite.objects.filter(auth_algorithm=value):
                c.auth_algorithm.vulnerabilities.add(vuln)
        elif attribute == 'enc_algorithm':
            for c in CipherSuite.objects.filter(enc_algorithm=value):
                c.enc_algorithm.vulnerabilities.add(vuln)
        elif attribute == 'hash_algorithm':
            for c in CipherSuite.objects.filter(hash_algorithm=value):
                c.hash_algorithm.vulnerabilities.add(vuln)


    def add_arguments(self, parser):
        parser.add_argument('file_path')


    def handle(self, *args, **options):
        complete_path = abspath(options['file_path'])
        vulns_created = 0
        with open(complete_path, 'r') as f:
            lines = f.readlines()
            for l in lines:
                try:
                    nam, sev, desc = l.split(';')
                except ValueError:
                    pass
                v, c = Vulnerability.objects.get_or_create(
                    name = nam,
                    severity = sev,
                    description = desc,
                )
                if c:
                    vulns_created += 1

        self.stdout.write(
            self.style.SUCCESS(
                'Successfully created {} new vulnerabilities'.format(vulns_created)
            )
        )

        self.add_vulnerability('protocol_version', 'TLS EXPORT', 'Export-grade cipher')
        self.add_vulnerability('auth_algorithm', 'anon', 'Anonymous key exchange')
        self.add_vulnerability('auth_algorithm', 'SHA', 'Secure Hash Algorithm 1')
        self.add_vulnerability('hash_algorithm', 'MD5', 'Message Digest 5')
        self.add_vulnerability('hash_algorithm', 'SHA', 'Secure Hash Algorithm 1')
