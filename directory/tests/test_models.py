from django.test import TestCase
from directory.models import CipherSuite, Rfc

class CipherSuiteBasicUnitTests(TestCase):
    def setUp(self):
        CipherSuite.objects.create(name='TSL_DH_WITH_AES_SHA')

    def test_string_representation(self):
        cs = CipherSuite.objects.get(name='TSL_DH_WITH_AES_SHA')
        self.assertEqual(cs.__str__(), cs.name)

    def test_member_attributes(self):
        cs = CipherSuite.objects.get(name='TSL_DH_WITH_AES_SHA')
        self.assertEqual(cs.prt, 'TSL')
        self.assertEqual(cs.kex, 'DH')
        self.assertEqual(cs.enc, 'AES')
        self.assertEqual(cs.mac, 'SHA')

class RfcBasicUnitTests(TestCase):
    def setUp(self):
        Rfc.objects.create(
            number=5246,
            status='Proposed Standard',
            title='The Transport Layer Security (TLS) Protocol Version 1.2',
            year=2008,
        )

    def test_string_representation(self):
        rfc = Rfc.objects.get(number=5246)
        self.assertEqual(rfc.__str__(), "RFC {}".format(rfc.number))

