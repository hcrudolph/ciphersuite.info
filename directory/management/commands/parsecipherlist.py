from django.core.management.base import BaseCommand, CommandError
from pathlib import Path
from os import linesep


class Command(BaseCommand):
    help = """Parses the output of openssl and gnutls-cli commands to create \
            a new fixture. Specifically, this commands expects output of either\
            `openssl -V` or `gnutls-cli -l`. The parameter `software` should be\
            either `openssl` or `gnutls`."""

    def __init__(self):
        self.openssl_tls_names = {}
        self.openssl_tls_names['TLSv1.3'] = 'TLS1.3'
        self.openssl_tls_names['TLSv1.2'] = 'TLS1.2'
        self.openssl_tls_names['TLSv1.1'] = 'TLS1.1'
        self.openssl_tls_names['TLSv1'] = 'TLS1.0'
        self.openssl_tls_names['SSLv3'] = 'SSL3'

        # inherit everything else from BaseCommand
        super().__init__()

    def add_arguments(self, parser):
        parser.add_argument("software", nargs=1, type=str)
        parser.add_argument("cipher_list", nargs=1, type=str)


    def create_fixture(self, ciphers, software):
        lines = []
        if software == "openssl":
            filename = "./directory/fixtures/02_openssl_ciphers.yaml"
        elif software == "gnutls":
            filename = "./directory/fixtures/03_gnutls_ciphers.yaml"
        else:
            filename = ""

        for c in ciphers:
            if software == "openssl":
                lines.append(f"- model: directory.OpensslCipher{linesep}")
            elif software == "gnutls":
                lines.append(f"- model: directory.GnutlsCipher{linesep}")

            lines.append(f"  pk: '{c['name']}'{linesep}")
            lines.append(f"  fields:{linesep}")
            lines.append(f"    hex_byte_1: '{c['hex1']}'{linesep}")
            lines.append(f"    hex_byte_2: '{c['hex2']}'{linesep}")
            lines.append(f"    min_tls_version: '{c['tlsv']}'{linesep}")

        file = Path(filename)
        if file.is_file():
            with open(file, 'w') as f:
                f.writelines(lines)
        else:
            raise CommandError(f"Cannot locate fixture file '{filename}'.\
                               Execute command in the project root folder.")


    def parse_gnutls_file(self, file):
        ciphers = []
        try:
            with open(file, 'r') as f:
                for line in f:
                    if line.startswith("TLS"):
                        ciphers.append(self.parse_gnutls_line(line))
                    else:
                        continue

                return ciphers

        except:
            raise CommandError("Failed to open cipher_list.")


    def parse_openssl_file(self, file):
        ciphers = []
        try:
            with open(file, 'r') as f:
                for line in f:
                    ciphers.append(self.parse_openssl_line(line))

                return ciphers

        except:
            raise CommandError("Failed to open cipher_list.")


    def parse_gnutls_line(self, line):
        items = line.split()
        cs = dict()
        cs['name'] = items[0]
        cs['hex1'] = items[1].strip(',')
        cs['hex2'] = items[2]
        cs['tlsv'] = items[3]
        return cs


    def parse_openssl_line(self, line):
        items = line.split()
        cs = dict()
        cs['name'] = items[2]
        cs['hex1'], cs['hex2'] = items[0].split(',')
        cs['tlsv'] = self.openssl_tls_names[items[3]]
        return cs


    def handle(self, *args, **options):
        """Main function to be run when command is executed."""
        file_path = options["cipher_list"][0]
        software = options["software"][0]

        if software == "gnutls":
            cipher_list = self.parse_gnutls_file(file_path)
        elif software == "openssl":
            cipher_list = self.parse_openssl_file(file_path)
        else:
            raise CommandError("Unexpected `software` value. Expecting either\
                               `openssl` or `gnutls`.")

        count = len(cipher_list)
        self.stdout.write(
            f"Found {count} ciphers suites."
        )
        self.create_fixture(cipher_list, software)
        self.stdout.write(
            self.style.SUCCESS(
                f"Created {count} ciphers suites."
            )
        )