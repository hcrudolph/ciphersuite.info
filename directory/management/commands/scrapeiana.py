from django.core.management.base import BaseCommand, CommandError
from directory.models import CipherSuite, Rfc
from os import linesep
from requests import get
import re

class FailedDownloadException(Exception):
    pass

class Command(BaseCommand):
    help = 'Scrapes TLS cipher suites from iana.org'

    # definition of generic filters for TLS ciphers
    # only fieldnames that contain (re.search) a
    # given regex will be added to the database
    # format: (fieldname, regex)
    def __init__(self):
        self.positive_filters = [
            ('name', 'Unassigned'),
            ('name', 'Reserved'),
            ('name', 'EMPTY'),
            ('name', 'FALLBACK'),
        ]
        self.negative_filters = [
            ('name', 'TLS'),
        ]
        # inherit everything else from BaseCommand
        super().__init__()

    def get_csv(self, url='https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv'):
        """Tries to download the content at the specified URL,
        returning the response in plain text format. If status code
        equals anything else than 200, FailedDownloadException is thrown"""

        response = get(url)
        if response.status_code == 200:
            return response.text
        else:
            raise FailedDownloadException()

    def split_line(self, line):
        result = dict()
        info = line.split(',')

        result['hex1'] = re.search(r'0x[0-9A-F]{2}', info[0]).group(0)
        result['hex2'] = re.search(r'0x[0-9A-F]{2}', info[1]).group(0)
        result['name'] = info[2]
        # info[3] = DTLS-OK
        # info[4] = Recommended
        result['rfcs'] = re.search(r'\[(RFC\d+)\]', info[5]).groups()

        return result

    def handle(self, *args, **options):
        """Main function to be run when command is executed."""

        verbosity = int(options['verbosity'])
        # try downloading csv file
        try:
            csv_file = self.get_csv()
        except:
            raise CommandError("Failed to download resource from the given URL.")

        # counter for successfully inserted or found ciphers
        cs_new = cs_old = rfc_new = 0
        for line in csv_file.split(linesep):
            # try splitting line its separate components or skip it
            try:
                d = self.split_line(line)
            except:
                if verbosity > 1:
                    self.stdout.write(
                        self.style.NOTICE("Failed to split line. Skipping.")
                    )
                continue

            # if any filters don't match, skip current cipher suite
            if not all(re.search(f[1], d[f[0]], re.IGNORECASE) for f in self.negative_filters):
                if verbosity > 1:
                    self.stdout.write(
                        self.style.NOTICE("Failed to parse line. Skipping.")
                    )
                continue

            # if any filters do match, skip current cipher suite
            if any(re.search(f[1], d[f[0]]) for f in self.positive_filters):
                if verbosity > 1:
                    self.stdout.write(
                        self.style.NOTICE("Failed to parse line. Skipping.")
                    )
                continue

            # create model instances in DB
            c, cstat = CipherSuite.objects.get_or_create(
                name = d['name'],
                hex_byte_1 = d['hex1'],
                hex_byte_2 = d['hex2'],
            )

            for rfc in d['rfcs']:
                regular_rfc = re.match(r'RFC(\d+)', rfc)
                draft_rfc   = re.match(r'RFC-ietf-tls-rfc(\d+).+', rfc)

                if regular_rfc is not None:
                    rfc_nr = regular_rfc.group(1)
                    draft_status = False
                elif draft_rfc is not None:
                    rfc_nr = draft_rfc.group(1)
                    draft_status = True

                r, rstat = Rfc.objects.get_or_create(
                    number = rfc_nr,
                    is_draft = draft_status
                )
                c.defining_rfcs.add(r)

                if rstat:
                    rfc_new += 1
                    if verbosity > 2:
                        self.stdout.write(
                            self.style.SUCCESS(
                                f"Successfully created RFC '{r.number}'."
                            )
                        )

            if cstat:
                cs_new += 1
                if verbosity > 2:
                    self.stdout.write(
                            self.style.SUCCESS(
                                f"Successfully created Ciphersuite '{c.name}'."
                            )
                        )
            else:
                cs_old += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Successfully created {cs_new} ({cs_old}) cipher suites and {rfc_new} RFCs."
            )
        )
