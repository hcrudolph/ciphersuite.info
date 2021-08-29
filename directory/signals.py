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

    def get_year(response):
        tree = html.fromstring(response.content)
        docinfo = " ".join(
            tree.xpath('//pre[1]/text()')
        )
        month_list = ['January', 'February', 'March', 'April', 'May', 'June',
            'July', 'August', 'September', 'October', 'November', 'December']
        month_and_year = re.compile(
            r'\b(?:%s)\b.*?(\d{4})' % '|'.join(month_list)
        )
        match = month_and_year.search(docinfo)
        return int(match.group(1))

    def get_title(response):
        tree = html.fromstring(response.content)
        headers = tree.xpath('//span[@class="h1"]/text()')
        return " ".join(headers)

    def get_status(response):
        tree = html.fromstring(response.content)
        # concat all fields possibly containing doc status
        docinfo = " ".join(
            tree.xpath('//span[@class="pre noprint docinfo"]/text()')
        )

        # search for predefined options
        if re.search('INTERNET STANDARD', docinfo):
            return 'IST'
        elif re.search('PROPOSED STANDARD', docinfo):
            return 'PST'
        elif re.search('DRAFT STANDARD', docinfo):
            return 'DST'
        elif re.search('BEST CURRENT PRACTISE', docinfo):
            return 'BCP'
        elif re.search('INFORMATIONAL', docinfo):
            return 'INF'
        elif re.search('EXPERIMENTAL', docinfo):
            return 'EXP'
        elif re.search('HISTORIC', docinfo):
            return 'HST'
        else:
            return 'UND'

    if instance.is_draft:
        url = f"https://tools.ietf.org/html/draft-ietf-tls-rfc{instance.number}"
    else:
        url = f"https://tools.ietf.org/html/rfc{instance.number}"
    resp = requests.get(url)
    if resp.status_code == 200:
        instance.url  = url
        instance.title = get_title(resp)
        instance.status = get_status(resp)
        instance.release_year = get_year(resp)
    else:
        # cancel saving the instance if unable to receive web page
        raise Exception('RFC not found')


@receiver(pre_save, sender=CipherSuite)
def complete_cs_instance(sender, instance, *args, **kwargs):
    '''Derives related algorithms form instance.name of the cipher suites.'''

    # TLS1.3 ciphers start with 0x13
    if instance.hex_byte_1 == '0x13' or instance.hex_byte_2 == '0xC6' or instance.hex_byte_2 == '0xC7':
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

    # if aut is not excplicitly defined, set it equal to kex
    if not aut:
        instance.auth_algorithm, _ = AuthAlgorithm.objects.get_or_create(
            short_name=kex.strip()
        )
    else:
        instance.auth_algorithm, _ = AuthAlgorithm.objects.get_or_create(
            short_name=aut.strip()
        )

    # connect foreign keys from other models
    instance.kex_algorithm, _ = KexAlgorithm.objects.get_or_create(
        short_name=kex.strip()
    )

    instance.protocol_version, _ = ProtocolVersion.objects.get_or_create(
        short_name=prt.strip()
    )
    instance.enc_algorithm, _ = EncAlgorithm.objects.get_or_create(
        short_name=enc.strip()
    )
    instance.hash_algorithm, _ = HashAlgorithm.objects.get_or_create(
        short_name=hsh.strip()
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
