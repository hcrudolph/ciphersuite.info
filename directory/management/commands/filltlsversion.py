from django.core.management.base import BaseCommand, CommandError
from directory.models import CipherSuite, TlsVersion

class Command(BaseCommand):
    # definition of generic filters for TLS ciphers
    # only fieldnames that contain (re.search) a
    # given regex will be added to the database
    # format: (fieldname, regex)
    def __init__(self):
        # inherit everything from BaseCommand
        super().__init__()


    def handle(self, *args, **options):
        """Main function to be run when command is executed."""

        # TLS1.2-only ciphers not identifiable by a single certain algorithm
        # TODO: find a better way to map these to TLS1.2
        misc_tls12 = [
            'TLS_RSA_WITH_NULL_SHA256',
            'TLS_RSA_WITH_AES_128_CBC_SHA256',
            'TLS_RSA_WITH_AES_256_CBC_SHA256',
            'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
            'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
            'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
            'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
            'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
            'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
            'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
            'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
            'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',
            'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
            'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
            'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
            'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
            'TLS_DH_anon_WITH_AES_128_CBC_SHA256',
            'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
            'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
            'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
            'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
            'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
            'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
            'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384',
            'TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
            'TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384',
        ]

        for cipher_suite in CipherSuite.objects.all():
            # IDEA and DES are deprecated with TLS1.2
            if 'IDEA' in cipher_suite.name or 'DES' in cipher_suite.name:
                tls10, _ = TlsVersion.objects.get_or_create(major=1, minor=0)
                tls11, _ = TlsVersion.objects.get_or_create(major=1, minor=1)
                cipher_suite.tls_version.add(tls10)
                cipher_suite.tls_version.add(tls11)
            # ChaCha/Poly, GCM and CCM are TLS1.2-only
            elif 'POLY1305' in cipher_suite.name or 'GCM' in cipher_suite.name or 'CCM' in cipher_suite.name:
                tls12, _ = TlsVersion.objects.get_or_create(major=1, minor=2)
                cipher_suite.tls_version.add(tls12)
            # catch some others by name
            elif cipher_suite.name in misc_tls12:
                tls12, _ = TlsVersion.objects.get_or_create(major=1, minor=2)
                cipher_suite.tls_version.add(tls12)
            # default is support by all TLS versions
            else:
                tls10, _ = TlsVersion.objects.get_or_create(major=1, minor=0)
                tls11, _ = TlsVersion.objects.get_or_create(major=1, minor=1)
                tls12, _ = TlsVersion.objects.get_or_create(major=1, minor=2)
                cipher_suite.tls_version.add(tls10)
                cipher_suite.tls_version.add(tls11)
                cipher_suite.tls_version.add(tls12)
            cipher_suite.save()

