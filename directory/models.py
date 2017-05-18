from django.db import models
from django.utils.translation import ugettext_lazy as _
from django.db.models.signals import pre_save
from django.dispatch import receiver

import requests
from lxml import html
import re


class CipherSuite(models.Model):
    class Meta:
        ordering=['name']
        verbose_name=_('cipher suite')
        verbose_name_plural=_('cipher suites')

    name = models.CharField(
        primary_key=True,
        max_length=200,
    )
    # protocol version (SSL, TLS, etc.)
    protocol_version = models.ForeignKey(
        'ProtocolVersion',
        verbose_name=_('protocol version'),
        editable=False,
    )
    # key exchange algorithm
    kex_algorithm = models.ForeignKey(
        'KexAlgorithm',
        verbose_name=_('key exchange algorithm'),
        editable=False,
    )
    # encryption algorithm
    enc_algorithm = models.ForeignKey(
        'EncAlgorithm',
        verbose_name=_('encryption algorithm'),
        editable=False,
    )
    # message authentication code algorithm
    hash_algorithm = models.ForeignKey(
        'HashAlgorithm',
        verbose_name=_('hash algorithm'),
        editable=False,
    )

    def save(self):
        # derive related algorithms form self.name
        (prt,_,rest) = self.name.replace("_", " ").partition(" ")
        (kex,_,rest) = rest.partition("WITH")
        (enc,_,hash) = rest.rpartition(" ")

        self.protocol_version, _ = ProtocolVersion.objects.get_or_create(
            short_name=prt.strip()
        )
        self.kex_algorithm, _ = KexAlgorithm.objects.get_or_create(
            short_name=kex.strip()
        )
        self.enc_algorithm, _ = EncAlgorithm.objects.get_or_create(
            short_name=enc.strip()
        )
        self.hash_algorithm, _ = HashAlgorithm.objects.get_or_create(
            short_name=hash.strip()
        )

        super(CipherSuite, self).save()

    def __str__(self):
        return self.name


class Rfc(models.Model):
    class Meta:
        verbose_name='RFC'
        verbose_name_plural='RFCs'
        ordering=['number']

    number = models.IntegerField(
        primary_key=True,
    )
    # predefined choices for document status
    IST = 'IST'
    PST = 'PST'
    DST = 'DST'
    BCP = 'BCP'
    INF = 'INF'
    EXP = 'EXP'
    HST = 'HST'
    UND = 'UND'
    STATUS_CHOICES = (
        (IST, 'Internet Standard'),
        (PST, 'Proposed Standard'),
        (DST, 'Draft Standard'),
        (BCP, 'Best Current Practise'),
        (INF, 'Informational'),
        (EXP, 'Experimental'),
        (HST, 'Historic'),
        (UND, 'Undefined'),
    )
    status = models.CharField(
        max_length=3,
        choices=STATUS_CHOICES,
        editable=False,
    )
    title = models.CharField(
        max_length=250,
        editable=False,
    )
    release_year = models.IntegerField(
        editable=False,
    )
    url = models.URLField(
        editable=False,
    )
    defined_cipher_suites = models.ManyToManyField(
        'CipherSuite',
        verbose_name=_('defined cipher suites'),
        related_name='defining_rfcs',
        blank=True,
    )
    related_documents = models.ManyToManyField(
        'self',
        verbose_name=_('related RFCs'),
        blank=True,
    )

    def __str__(self):
        return "RFC {}".format(self.number)


class Technology(models.Model):
    class Meta:
        abstract=True
        ordering=['short_name']

    short_name = models.CharField(
        primary_key=True,
        max_length=20,
    )
    long_name = models.CharField(
        max_length=100,
    )
    vulnerabilities = models.ManyToManyField(
        'Vulnerability',
        blank=True,
    )

    def __str__(self):
        return self.short_name


class ProtocolVersion(Technology):
    class Meta(Technology.Meta):
        verbose_name=_('protocol version')
        verbose_name_plural=_('protocol versions')


class KexAlgorithm(Technology):
    class Meta(Technology.Meta):
        verbose_name=_('key exchange algorithm')
        verbose_name_plural=_('key exchange algorithms')


class EncAlgorithm(Technology):
    class Meta(Technology.Meta):
        verbose_name=_('encryption algorithm')
        verbose_name_plural=_('encryption algorithms')


class HashAlgorithm(Technology):
    class Meta(Technology.Meta):
        verbose_name=_('hash algorithm')
        verbose_name_plural=_('hash algorithms')


class Vulnerability(models.Model):
    class Meta:
        ordering=['name']
        verbose_name=_('vulnerability')
        verbose_name_plural=_('vulnerabilities')

    name = models.CharField(
        max_length=50,
    )
    description = models.TextField(
        max_length=1000,
        blank=True,
    )
    cve_id = models.CharField(
        max_length=100,
        blank=True,
    )

    def __str__(self):
        return self.name

def get_text(url):
    return requests.get(url).text

def get_year(url):
    text = requests.get(url).text
    match = re.search('(\d{4})\s*<span class="h1">', text)
    return int(match.group(1))

def get_title(url):
    text = requests.get(url).content
    tree = html.fromstring(text)
    headers = tree.xpath('//span[@class="h1"]/text()')
    return " ".join(headers)

def get_status(url):
    text = requests.get(url).content
    tree = html.fromstring(text)
    docinfos = tree.xpath('//span[@class="pre noprint docinfo"]/text()')
    infostring = " ".join(docinfos)

    if re.search('INTERNET STANDARD', infostring):
        return 'IST'
    elif re.search('PROPOSED STANDARD', infostring):
        return 'PST'
    elif re.search('DRAFT STANDARD', infostring):
        return 'DST'
    elif re.search('BEST CURRENT PRACTISE', infostring):
        return 'BCP'
    elif re.search('INFORMATIONAL', infostring):
        return 'INF'
    elif re.search('EXPERIMENTAL', infostring):
        return 'EXP'
    elif re.search('HISTORIC', infostring):
        return 'HST'
    else:
        return 'UND'


@receiver(pre_save, sender=Rfc)
def populate_rfc(sender, instance, *args, **kwargs):
    url = "https://tools.ietf.org/html/rfc{}".format(instance.number)
    instance.url  = url
    instance.text = get_text(url)
    instance.release_year = get_year(url)
    instance.title = get_title(url)
    instance.status = get_status(url)

