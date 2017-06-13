from django.core.management.base import BaseCommand, CommandError
from directory.models import CipherSuite, Rfc

from os import linesep
from requests import get
import re

class Command(BaseCommand):
    help = 'Scrapes TLS cipher suites from iana.org'

    # definition of generic filters for TLS ciphers
    # only fieldnames that contain (re.search) a
    # given regex will be added to the database
    # format: (fieldname, regex)
    def __init__(self):
        self.filters = [
            ('name', 'WITH'),
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
            raise FailedDownloadException(
                "Failed to download resource from the given URL."
            )


    def split_line(self, line):
        result = dict()
        info = line.split(',')

        result['hex1'] = re.search('0x[0123456789ABCDEF]{2}', info[0]).group(0)
        result['hex2'] = re.search('0x[0123456789ABCDEF]{2}', info[1]).group(0)
        result['name'] = info[2]
        # info[3] is DTLS
        result['rfcs'] = re.search('\[(RFC.+?)\]', info[4]).groups()

        return result

    def handle(self, *args, **options):
        """Main function to be run when command is executed."""

        # try downloading csv file
        try:
            csv_file = self.get_csv()
        except FailedDownloadException as e:
            self.stdout.write(self.style.ERROR(e.message))

        # counter for successfully inserted or found ciphers
        cs_new, cs_old, rfc_new = 0, 0, 0
        for line in csv_file.split(linesep):
            # try splitting line its separate components or continue
            try:
                d = self.split_line(line)
            except:
                continue

            # if any of our filters don't match, skip current cipher suite
            if not all(re.search(f[1], d[f[0]]) for f in self.filters):
                continue

            # create model instances in DB
            c, cstat = CipherSuite.objects.get_or_create(
                name = d['name'],
                hex_byte_1 = d['hex1'],
                hex_byte_2 = d['hex2'],
            )

            for rfc in d['rfcs']:
                regular_rfc = re.match('RFC(\d+)', rfc)
                draft_rfc   = re.match('RFC-ietf-tls-rfc(\d+).+', rfc)

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

            if cstat:
                cs_new += 1
            else:
                cs_old += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Successfully created {cs_new} cipher suites and {rfc_new} RFCs. " +
                f"{cs_old} cipher suites already in the database."
            )
        )


class FailedDownloadException(Exception):
    pass
