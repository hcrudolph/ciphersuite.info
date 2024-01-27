from django.core.exceptions import ObjectDoesNotExist
from django.db.models.signals import pre_save
from django.dispatch import receiver
from directory.models import *
from lxml import html
import requests
import re


@receiver(pre_save, sender=Rfc)
def complete_rfc_instance(sender, instance, *args, **kwargs):
    """Automatically fetches general document information
    from ietf.org before saving RFC instance."""

    def get_year(html):
        docinfo = " ".join(
            html.xpath('//tbody[@class="meta align-top  border-top"]/tr/td[2]/text()')
        ).strip()
        month_list = ['January', 'February', 'March', 'April', 'May', 'June',
            'July', 'August', 'September', 'October', 'November', 'December']
        month_and_year = re.compile(
            r'\b(?:%s)\b.*?(\d{4})' % '|'.join(month_list)
        )
        match = month_and_year.search(docinfo)
        return int(match.group(1))

    def get_title(html):
        docinfo = " ".join(html.xpath('//h1/text()'))
        return docinfo.strip()

    def get_status(html):
        # get table with document properties
        docinfo = " ".join(
            html.xpath('//td/*[contains(text(),"RFC")]/text()')
        ).strip()

        # search for predefined options
        if re.search('INTERNET STANDARD', docinfo, re.IGNORECASE):
            return 'IST'
        elif re.search('PROPOSED STANDARD', docinfo, re.IGNORECASE):
            return 'PST'
        elif re.search('DRAFT STANDARD', docinfo, re.IGNORECASE):
            return 'DST'
        elif re.search('BEST CURRENT PRACTISE', docinfo, re.IGNORECASE):
            return 'BCP'
        elif re.search('INFORMATIONAL', docinfo, re.IGNORECASE):
            return 'INF'
        elif re.search('EXPERIMENTAL', docinfo, re.IGNORECASE):
            return 'EXP'
        elif re.search('HISTORIC', docinfo, re.IGNORECASE):
            return 'HST'
        else:
            return 'UND'

    url = f"https://datatracker.ietf.org/doc/rfc{instance.number}"
    rfc = requests.get(url)
    if rfc.status_code == 200:
        content = html.fromstring(rfc.content)
        instance.url  = url
        instance.title = get_title(content)
        instance.status = get_status(content)
        instance.release_year = get_year(content)
    else:
        # cancel saving the instance if unable to receive web page
        raise Exception('RFC not found')


@receiver(pre_save, sender=CipherSuite)
def complete_cs_instance(sender, instance, *args, **kwargs):
    '''Derives related algorithms form instance.name of the cipher suites.'''

    flag_tls13 = False
    flag_pfs = False
    flag_aead = False

    # GOST ciphers
    if (instance.hex_byte_1 == '0xC1' and instance.hex_byte_2 == '0x00') or\
        (instance.hex_byte_1 == '0xC1' and instance.hex_byte_2 == '0x01') or\
        (instance.hex_byte_1 == '0xC1' and instance.hex_byte_2 == '0x02') or\
        (instance.hex_byte_1 == '0xC1' and instance.hex_byte_2 == '0x03') or\
        (instance.hex_byte_1 == '0xC1' and instance.hex_byte_2 == '0x04') or\
        (instance.hex_byte_1 == '0xC1' and instance.hex_byte_2 == '0x05') or\
        (instance.hex_byte_1 == '0xC1' and instance.hex_byte_2 == '0x06'):
        name = instance.name
        (fst,_,rst) = name.replace("_", " ").partition("WITH")
        (prt,kex) = fst.split(" ", 1)
        aut = 'GOSTR341012'
        hsh = 'GOSTR341112'

        if re.search(r'MGM', rst, re.IGNORECASE):
            flag_tls13 = True
            kex = 'ECDHE'
            enc = rst
            aut = '-'
            hsh = '-'
        else:
            (enc,_) = rst.rsplit(" ", 1)

    # TLS1.3 authentication/integrity-only ciphers
    elif (instance.hex_byte_1 == '0xC0' and instance.hex_byte_2 == '0xB4') or\
        (instance.hex_byte_1 == '0xC0' and instance.hex_byte_2 == '0xB5'):
        flag_tls13 = True
        name = instance.name
        (prt,_,rst) = name.replace("_", " ").partition(" ")
        (aut,_,hsh) = rst.rpartition(" ")
        enc = "NULL"
        kex = "-"

    # TLS1.3 ciphers
    elif instance.hex_byte_1 == '0x13'\
        or instance.hex_byte_2 == '0xC6'\
        or instance.hex_byte_2 == '0xC7':
        flag_tls13 = True
        name = instance.name
        (prt,_,rst) = name.replace("_", " ").partition(" ")
        (enc,_,hsh) = rst.rpartition(" ")
        aut = "-"
        kex = "-"

    else:
        # EXPORT substring does not describe any algorithm, so we remove it
        # substring is later appended to the protocol_version
        if re.search("EXPORT", instance.name):
            name = instance.name.replace('EXPORT_', '')
            export_cipher = True
        else:
            name = instance.name
            export_cipher = False

        (prt,_,rst) = name.replace("_", " ").partition(" ")
        (kex,_,rst) = rst.partition("WITH")

        # add information about export-grade cipher to protocol version
        if export_cipher:
            prt += " EXPORT"

        # split kex again, potentially yielding auth algorithm
        # otherwise this variable will remain unchanged
        (kex,_,aut) = kex.partition(" ")
        (enc,_,hsh) = rst.rpartition(" ")

        # split enc again if we only got a number for hsh
        # specifically needed for CCM/CCM8 ciphers
        if re.match(r'\d+', hsh.strip()) or re.match(r'CCM\Z', hsh.strip()):
            enc += " " + hsh
            hsh = "SHA256"

        if kex.strip() == "PSK" and aut.strip() == "DHE":
            kex = "DHE"
            aut = "PSK"

    # identify PFS algorithms
    if re.search(r'ECDHE|DHE', kex, re.IGNORECASE) or flag_tls13:
        flag_pfs = True

    # identify AEAD algorithms
    if re.search(r'GCM|POLY1305|CCM|MGM', enc, re.IGNORECASE):
        flag_aead = True

    # connect foreign keys from other models
    # if aut is not excplicitly defined, set it equal to kex
    if not aut:
        instance.auth_algorithm, _ = AuthAlgorithm.objects.get_or_create(
            short_name=kex.strip()
        )
    else:
        instance.auth_algorithm, _ = AuthAlgorithm.objects.get_or_create(
            short_name=aut.strip()
        )
    instance.kex_algorithm, _ = KexAlgorithm.objects.update_or_create(
        short_name=kex.strip(),
        defaults={'pfs_support': flag_pfs}
    )
    instance.protocol_version, _ = ProtocolVersion.objects.get_or_create(
        short_name=prt.strip()
    )
    instance.hash_algorithm, _ = HashAlgorithm.objects.get_or_create(
        short_name=hsh.strip()
    )
    instance.enc_algorithm, _ = EncAlgorithm.objects.update_or_create(
        short_name=enc.strip(),
        defaults={'aead_algorithm': flag_aead}
    )


@receiver(pre_save, sender=CipherSuite)
def complete_cs_names(sender, instance, *args, **kwargs):
    try:
        related_gnutls = GnutlsCipher.objects.get(hex_byte_1__iexact=instance.hex_byte_1,
                                                  hex_byte_2__iexact=instance.hex_byte_2)
        instance.gnutls_name = related_gnutls.name
    except ObjectDoesNotExist:
        pass

    try:
        related_openssl = OpensslCipher.objects.get(hex_byte_1__iexact=instance.hex_byte_1,
                                                    hex_byte_2__iexact=instance.hex_byte_2)
        instance.openssl_name = related_openssl.name
    except ObjectDoesNotExist:
        pass


@receiver(pre_save, sender=TlsVersion)
def complete_tls_version(sender, instance, *args, **kwargs):
    instance.short = f"{instance.major}{instance.minor}"


@receiver(pre_save, sender=StaticPage)
def complete_cs_names(sender, instance, *args, **kwargs):
    if instance.show_in_nav == False:
        instance.direct_link = False
