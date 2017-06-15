from django.test import TestCase
from directory.models import *

class CipherSuiteRegularUnitTests(TestCase):
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


class CipherSuiteNoAuthUnitTests(TestCase):
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


class CipherSuiteExportUnitTests(TestCase):
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


class CipherSuiteCCM8UnitTests(TestCase):
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


class RfcRegularUnitTests(TestCase):
    rfc_number = 5246
    rfc_year = 2008
    rfc_title = 'The Transport Layer Security (TLS) Protocol Version 1.2'
    rfc_status = 'PST'
    rfc_draft = False

    def setUp(self):
        Rfc.objects.create(number=self.rfc_number)

    def test_string_representation(self):
        rfc = Rfc.objects.get(number=self.rfc_number)
        self.assertEqual(rfc.__str__(), f"RFC {self.rfc_number}")
    
    def test_member_attributes(self):
        rfc = Rfc.objects.get(number=self.rfc_number)
        self.assertEqual(rfc.title.__str__(), self.rfc_title)
        self.assertEqual(rfc.status.__str__(), self.rfc_status)
        self.assertEqual(rfc.is_draft.__str__(), f"{self.rfc_draft}")
        self.assertEqual(rfc.release_year.__str__(), f"{self.rfc_year}")
    

class RfcDraftUnitTests(TestCase):
    rfc_number = 4492
    rfc_year = 2017
    rfc_title = 'Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier draft-ietf-tls-rfc4492bis-17'
    rfc_status = 'UND'
    rfc_draft = True

    def setUp(self):
        Rfc.objects.create(
            number=self.rfc_number,
            is_draft=self.rfc_draft,
        )

    def test_string_representation(self):
        rfc = Rfc.objects.get(number=self.rfc_number)
        self.assertEqual(rfc.__str__(), f"DRAFT RFC {self.rfc_number}")
    
    def test_member_attributes(self):
        rfc = Rfc.objects.get(number=self.rfc_number)
        self.assertEqual(rfc.title.__str__(),self.rfc_title)
        self.assertEqual(rfc.status.__str__(), self.rfc_status)
        self.assertEqual(rfc.is_draft.__str__(), f"{self.rfc_draft}")
        self.assertEqual(rfc.release_year.__str__(), f"{self.rfc_year}")