# django imports
from django.db import models
from django.utils.translation import ugettext_lazy as _
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.db.models import Q

# general python imports
from lxml import html
import requests
import re


#####################
# Model definitions #
#####################

class CipherSuiteQuerySet(models.QuerySet):
    def none(self):
        return self.all().exclude(
            Q(protocol_version__vulnerabilities__severity='HIG')|
            Q(protocol_version__vulnerabilities__severity='MED')|
            Q(protocol_version__vulnerabilities__severity='LOW')|
            Q(kex_algorithm__vulnerabilities__severity='HIG')|
            Q(kex_algorithm__vulnerabilities__severity='MED')|
            Q(kex_algorithm__vulnerabilities__severity='LOW')|
            Q(enc_algorithm__vulnerabilities__severity='HIG')|
            Q(enc_algorithm__vulnerabilities__severity='MED')|
            Q(enc_algorithm__vulnerabilities__severity='LOW')|
            Q(auth_algorithm__vulnerabilities__severity='HIG')|
            Q(auth_algorithm__vulnerabilities__severity='MED')|
            Q(auth_algorithm__vulnerabilities__severity='LOW')|
            Q(hash_algorithm__vulnerabilities__severity='HIG')|
            Q(hash_algorithm__vulnerabilities__severity='MED')|
            Q(hash_algorithm__vulnerabilities__severity='LOW')
        )

    def low(self):
        low = self.filter(
            Q(protocol_version__vulnerabilities__severity='LOW')|
            Q(kex_algorithm__vulnerabilities__severity='LOW')|
            Q(enc_algorithm__vulnerabilities__severity='LOW')|
            Q(auth_algorithm__vulnerabilities__severity='LOW')|
            Q(hash_algorithm__vulnerabilities__severity='LOW')
        )
        return low.exclude(
            Q(protocol_version__vulnerabilities__severity='HIG')|
            Q(protocol_version__vulnerabilities__severity='MED')|
            Q(kex_algorithm__vulnerabilities__severity='HIG')|
            Q(kex_algorithm__vulnerabilities__severity='MED')|
            Q(enc_algorithm__vulnerabilities__severity='HIG')|
            Q(enc_algorithm__vulnerabilities__severity='MED')|
            Q(auth_algorithm__vulnerabilities__severity='HIG')|
            Q(auth_algorithm__vulnerabilities__severity='MED')|
            Q(hash_algorithm__vulnerabilities__severity='HIG')|
            Q(hash_algorithm__vulnerabilities__severity='MED')
        )

    def medium(self):
        medium = self.filter(
            Q(protocol_version__vulnerabilities__severity='MED')|
            Q(kex_algorithm__vulnerabilities__severity='MED')|
            Q(enc_algorithm__vulnerabilities__severity='MED')|
            Q(auth_algorithm__vulnerabilities__severity='MED')|
            Q(hash_algorithm__vulnerabilities__severity='MED')
        )
        return medium.exclude(
            Q(protocol_version__vulnerabilities__severity='HIG')|
            Q(kex_algorithm__vulnerabilities__severity='HIG')|
            Q(enc_algorithm__vulnerabilities__severity='HIG')|
            Q(auth_algorithm__vulnerabilities__severity='HIG')|
            Q(hash_algorithm__vulnerabilities__severity='HIG')
        )

    def high(self):
        return self.filter(
            Q(protocol_version__vulnerabilities__severity='HIG')|
            Q(kex_algorithm__vulnerabilities__severity='HIG')|
            Q(enc_algorithm__vulnerabilities__severity='HIG')|
            Q(auth_algorithm__vulnerabilities__severity='HIG')|
            Q(hash_algorithm__vulnerabilities__severity='HIG')
        )


class CipherSuite(models.Model):
    class Meta:
        ordering=['name']
        verbose_name=_('cipher suite')
        verbose_name_plural=_('cipher suites')
        # hex bytes identifiy cipher suite uniquely
        unique_together=(('hex_byte_1', 'hex_byte_2'),)

    # name of the cipher as defined by RFC
    name = models.CharField(
        primary_key=True,
        max_length=200,
    )
    # hex bytes stored as string 0x00-0xFF
    hex_byte_1 = models.CharField(
        max_length=4,
    )
    hex_byte_2 = models.CharField(
        max_length=4,
    )
    # protocol version
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
    # authentication algorithm
    auth_algorithm = models.ForeignKey(
        'AuthAlgorithm',
        verbose_name=_('authentication algorithm'),
        editable=False,
    )
    # encryption algorithm
    enc_algorithm = models.ForeignKey(
        'EncAlgorithm',
        verbose_name=_('encryption algorithm'),
        editable=False,
    )
    # hash algorithm
    hash_algorithm = models.ForeignKey(
        'HashAlgorithm',
        verbose_name=_('hash algorithm'),
        editable=False,
    )

    def get_vulnerabilities(self):
        return set().union(
            self.protocol_version.vulnerabilities.all().values_list('severity', flat=True),
            self.enc_algorithm.vulnerabilities.all().values_list('severity', flat=True),
            self.kex_algorithm.vulnerabilities.all().values_list('severity', flat=True),
            self.auth_algorithm.vulnerabilities.all().values_list('severity', flat=True),
            self.hash_algorithm.vulnerabilities.all().values_list('severity', flat=True)
        )

    @property
    def no_severity(self):
        vulnerabilities = self.get_vulnerabilities()
        if not any(vulnerabilities):
            return True
        else:
            return False

    @property
    def low_severity(self):
        vulnerabilities = self.get_vulnerabilities()
        if any([v for v in vulnerabilities if v=='LOW']):
            return True
        else:
            return False

    @property
    def med_severity(self):
        vulnerabilities = self.get_vulnerabilities()
        if any([v for v in vulnerabilities if v=='MED']):
            return True
        else:
            return False

    @property
    def high_severity(self):
        vulnerabilities = self.get_vulnerabilities()
        if any([v for v in vulnerabilities if v=='HIG']):
            return True
        else:
            return False

    objects = models.Manager()
    vulnerabilities = CipherSuiteQuerySet.as_manager()

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
    is_draft = models.BooleanField(
        editable=False,
        default=False,
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
        if self.is_draft:
            return f"DRAFT RFC {self.number}"
        else:
            return f"RFC {self.number}"


class Technology(models.Model):
    class Meta:
        abstract=True
        ordering=['short_name']

    short_name = models.CharField(
        primary_key=True,
        max_length=30,
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


class AuthAlgorithm(Technology):
    class Meta(Technology.Meta):
        verbose_name=_('authentication algorithm')
        verbose_name_plural=_('authentication algorithms')


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
        primary_key=True,
    )
    description = models.TextField(
        max_length=1000,
        blank=True,
    )
    HIG = 'HIG'
    MED = 'MED'
    LOW = 'LOW'
    SEVERITY_CHOICES = (
        (HIG, 'High'),
        (MED, 'Medium'),
        (LOW, 'Low'),
    )
    severity = models.CharField(
        max_length=3,
        choices=SEVERITY_CHOICES,
        default=LOW,
    )

    def __str__(self):
        return self.name


class StaticPage(models.Model):
    class Meta:
        ordering=['title']
        verbose_name=_('static page')
        verbose_name_plural=_('static pages')

    title = models.CharField(
        primary_key=True,
        max_length=50,
    )
    content = models.TextField(
        max_length = 10000,
    )
    glyphicon = models.CharField(
        max_length=50,
    )

    def __str__(self):
        return self.title


######################
# Signal definitions #
######################


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
    # specifically needed for 'CCM 8' hash algorithm
    if re.match('\d+', hsh.strip()):
        (enc,_,ccm) = enc.rpartition(" ")
        hsh = ccm + " " + hsh

    # connect foreign keys from other models
    instance.protocol_version, _ = ProtocolVersion.objects.get_or_create(
        short_name=prt.strip()
    )
    instance.kex_algorithm, _ = KexAlgorithm.objects.get_or_create(
        short_name=kex.strip()
    )
    instance.enc_algorithm, _ = EncAlgorithm.objects.get_or_create(
        short_name=enc.strip()
    )
    instance.hash_algorithm, _ = HashAlgorithm.objects.get_or_create(
        short_name=hsh.strip()
    )

    # if aut is not excplicitly defined, set it equal to kex
    if aut:
        instance.auth_algorithm, _ = AuthAlgorithm.objects.get_or_create(
            short_name=aut.strip()
        )
    else:
        instance.auth_algorithm, _ = AuthAlgorithm.objects.get_or_create(
            short_name=kex.strip()
        )
