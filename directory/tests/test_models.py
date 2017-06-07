from django.test import TestCase
from directory.models import *

class RegularCipherSuiteUnitTests(TestCase):
    cipher_suite = 'TLS_DH_DSS_WITH_AES_256_CBC_SHA'

    def setUp(self):
        CipherSuite.objects.create(name=self.cipher_suite)

    def test_string_representation(self):
        cs = CipherSuite.objects.get(name=self.cipher_suite)
        self.assertEqual(cs.__str__(), self.cipher_suite)

    def test_member_attributes(self):
        cs = CipherSuite.objects.get(name=self.cipher_suite)
        self.assertEqual(cs.protocol_version.__str__(), 'TLS')
        self.assertEqual(cs.kex_algorithm.__str__(), 'DH')
        self.assertEqual(cs.auth_algorithm.__str__(), 'DSS')
        self.assertEqual(cs.enc_algorithm.__str__(), 'AES 256 CBC')
        self.assertEqual(cs.hash_algorithm.__str__(), 'SHA')


class NoAuthCipherSuiteUnitTests(TestCase):
    cipher_suite = 'TLS_PSK_WITH_AES_128_CBC_SHA'

    def setUp(self):
        CipherSuite.objects.create(name=self.cipher_suite)

    def test_string_representation(self):
        cs = CipherSuite.objects.get(name=self.cipher_suite)
        self.assertEqual(cs.__str__(), self.cipher_suite)

    def test_member_attributes(self):
        cs = CipherSuite.objects.get(name=self.cipher_suite)
        self.assertEqual(cs.protocol_version.__str__(), 'TLS')
        self.assertEqual(cs.kex_algorithm.__str__(), 'PSK')
        self.assertEqual(cs.auth_algorithm.__str__(), 'PSK')
        self.assertEqual(cs.enc_algorithm.__str__(), 'AES 128 CBC')
        self.assertEqual(cs.hash_algorithm.__str__(), 'SHA')


class ExportCipherSuiteUnitTests(TestCase):
    cipher_suite = 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5'

    def setUp(self):
        CipherSuite.objects.create(name=self.cipher_suite)

    def test_string_representation(self):
        cs = CipherSuite.objects.get(name=self.cipher_suite)
        self.assertEqual(cs.__str__(), self.cipher_suite)

    def test_member_attributes(self):
        cs = CipherSuite.objects.get(name=self.cipher_suite)
        self.assertEqual(cs.protocol_version.__str__(), 'TLS EXPORT')
        self.assertEqual(cs.kex_algorithm.__str__(), 'DH')
        self.assertEqual(cs.auth_algorithm.__str__(), 'anon')
        self.assertEqual(cs.enc_algorithm.__str__(), 'RC4 40')
        self.assertEqual(cs.hash_algorithm.__str__(), 'MD5')


class CCM8CipherSuiteUnitTests(TestCase):
    cipher_suite = 'TLS_DHE_RSA_WITH_AES_256_CCM_8'

    def setUp(self):
        CipherSuite.objects.create(name=self.cipher_suite)

    def test_string_representation(self):
        cs = CipherSuite.objects.get(name=self.cipher_suite)
        self.assertEqual(cs.__str__(), self.cipher_suite)

    def test_member_attributes(self):
        cs = CipherSuite.objects.get(name=self.cipher_suite)
        self.assertEqual(cs.protocol_version.__str__(), 'TLS')
        self.assertEqual(cs.kex_algorithm.__str__(), 'DHE')
        self.assertEqual(cs.auth_algorithm.__str__(), 'RSA')
        self.assertEqual(cs.enc_algorithm.__str__(), 'AES 256')
        self.assertEqual(cs.hash_algorithm.__str__(), 'CCM 8')


# class RfcBasicUnitTests(TestCase):
#     def setUp(self):
#         Rfc.objects.create(
#             number=5246,
#             status='Proposed Standard',
#             title='The Transport Layer Security (TLS) Protocol Version 1.2',
#             year=2008,
#         )

#     def test_string_representation(self):
#         rfc = Rfc.objects.get(number=5246)
#         self.assertEqual(rfc.__str__(), "RFC {}".format(rfc.number))

