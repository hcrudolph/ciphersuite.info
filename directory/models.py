from django.utils.translation import ugettext_lazy as _
from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector
from django.db import models
from django.db.models import Q


class CipherSuiteQuerySet(models.QuerySet):
    def recommended(self):
        return self.exclude(
            Q(protocol_version__vulnerabilities__severity='HIG')|
            Q(protocol_version__vulnerabilities__severity='MED')|
            Q(kex_algorithm__vulnerabilities__severity='HIG')|
            Q(kex_algorithm__vulnerabilities__severity='MED')|
            Q(enc_algorithm__vulnerabilities__severity='HIG')|
            Q(enc_algorithm__vulnerabilities__severity='MED')|
            Q(auth_algorithm__vulnerabilities__severity='HIG')|
            Q(auth_algorithm__vulnerabilities__severity='MED')|
            Q(hash_algorithm__vulnerabilities__severity='HIG')|
            Q(hash_algorithm__vulnerabilities__severity='MED')|
            Q(enc_algorithm__short_name__icontains='CBC')| # CBC cipher
            Q(hash_algorithm__short_name__icontains='CCM') # CBC cipher
        ).filter(
            Q(kex_algorithm__short_name__icontains='DHE') # DHE = recommended cipher
        )

    def secure(self):
        return self.exclude(
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
        ).exclude(
            Q(kex_algorithm__short_name__icontains='DHE') # DHE = recommended cipher
        )

    def weak(self):
        return self.filter(
            Q(protocol_version__vulnerabilities__severity='MED')|
            Q(kex_algorithm__vulnerabilities__severity='MED')|
            Q(enc_algorithm__vulnerabilities__severity='MED')|
            Q(auth_algorithm__vulnerabilities__severity='MED')|
            Q(hash_algorithm__vulnerabilities__severity='MED')
        ).exclude(
            Q(protocol_version__vulnerabilities__severity='HIG')|
            Q(kex_algorithm__vulnerabilities__severity='HIG')|
            Q(enc_algorithm__vulnerabilities__severity='HIG')|
            Q(auth_algorithm__vulnerabilities__severity='HIG')|
            Q(hash_algorithm__vulnerabilities__severity='HIG')
        )

    def insecure(self):
        return self.filter(
            Q(protocol_version__vulnerabilities__severity='HIG')|
            Q(kex_algorithm__vulnerabilities__severity='HIG')|
            Q(enc_algorithm__vulnerabilities__severity='HIG')|
            Q(auth_algorithm__vulnerabilities__severity='HIG')|
            Q(hash_algorithm__vulnerabilities__severity='HIG')
        )

    def search(self, search_term):
        vector = SearchVector(
            'name',
            'openssl_name',
            'gnutls_name',
            'auth_algorithm__long_name',
            'enc_algorithm__long_name',
            'kex_algorithm__long_name',
            'hash_algorithm__long_name',
            'protocol_version__vulnerabilities__name',
            'auth_algorithm__vulnerabilities__name',
            'enc_algorithm__vulnerabilities__name',
            'kex_algorithm__vulnerabilities__name',
            'hash_algorithm__vulnerabilities__name',
            'protocol_version__vulnerabilities__description',
            'auth_algorithm__vulnerabilities__description',
            'enc_algorithm__vulnerabilities__description',
            'kex_algorithm__vulnerabilities__description',
            'hash_algorithm__vulnerabilities__description'
        )
        query = SearchQuery(search_term)
        return CipherSuite.objects.annotate(
            rank=SearchRank(vector, query)
        ).order_by('-rank')[:45]


class RfcQuerySet(models.QuerySet):
    def search(self, search_term):
        return self.filter(
            Q(title__icontains=search_term)|
            Q(number__icontains=search_term)
        )


class CipherImplementation(models.Model):
    class Meta:
        abstract=True
        ordering=['name']
        # hex bytes identifiy cipher suite uniquely
        unique_together=(('hex_byte_1', 'hex_byte_2'),)

    name = models.CharField(
        primary_key=True,
        max_length=200,
    )
    hex_byte_1 = models.CharField(
        max_length=4,
    )
    hex_byte_2 = models.CharField(
        max_length=4,
    )
    min_tls_version = models.CharField(
        max_length=20,
        blank=True,
        default='',
    )


class GnutlsCipher(CipherImplementation):
    class Meta(CipherImplementation.Meta):
        verbose_name=_('gnutls cipher')
        verbose_name_plural=_('gnutls ciphers')


class OpensslCipher(CipherImplementation):
    class Meta(CipherImplementation.Meta):
        verbose_name=_('openssl cipher')
        verbose_name_plural=_('openssl ciphers')


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
    gnutls_name = models.CharField(
        max_length=200,
        blank=True,
        default='',
    )
    openssl_name = models.CharField(
        max_length=200,
        blank=True,
        default='',
    )
    tls_version = models.CharField(
        max_length=50,
        blank=True,
        default='',
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
        on_delete=models.CASCADE,
        blank=True,
        default='',
    )
    # key exchange algorithm
    kex_algorithm = models.ForeignKey(
        'KexAlgorithm',
        verbose_name=_('key exchange algorithm'),
        on_delete=models.CASCADE,
        blank=True,
        default='',
    )
    # authentication algorithm
    auth_algorithm = models.ForeignKey(
        'AuthAlgorithm',
        verbose_name=_('authentication algorithm'),
        on_delete=models.CASCADE,
        blank=True,
        default='',
    )
    # encryption algorithm
    enc_algorithm = models.ForeignKey(
        'EncAlgorithm',
        verbose_name=_('encryption algorithm'),
        on_delete=models.CASCADE,
        blank=True,
        default='',
    )
    # hash algorithm
    hash_algorithm = models.ForeignKey(
        'HashAlgorithm',
        verbose_name=_('hash algorithm'),
        on_delete=models.CASCADE,
        blank=True,
        default='',
    )


    def __get_vulnerabilities(self):
        return set().union(
            self.protocol_version.vulnerabilities.all().values_list('severity', flat=True),
            self.enc_algorithm.vulnerabilities.all().values_list('severity', flat=True),
            self.kex_algorithm.vulnerabilities.all().values_list('severity', flat=True),
            self.auth_algorithm.vulnerabilities.all().values_list('severity', flat=True),
            self.hash_algorithm.vulnerabilities.all().values_list('severity', flat=True)
        )

    @property
    def insecure(self):
        vulnerabilities = self.__get_vulnerabilities()
        if any([v for v in vulnerabilities if v=='HIG']):
            return True
        else:
            return False

    @property
    def weak(self):
        vulnerabilities = self.__get_vulnerabilities()
        if not self.insecure and any([v for v in vulnerabilities if v=='MED']):
            return True
        else:
            return False

    @property
    def secure(self):
        if not self.insecure \
        and not self.weak \
        and not self.recommended:
            return True
        else:
            return False

    @property
    def recommended(self):
        if not self.insecure \
        and not self.weak \
        and ("DHE" in self.kex_algorithm.short_name) \
        and not ("CBC" in self.enc_algorithm.short_name) \
        and not ("CCM" in self.hash_algorithm.short_name):
            return True
        else:
            return False

    @property
    def gnutls_cipher(self):
        if self.gnutls_name:
            return True
        else:
            return False

    @property
    def openssl_cipher(self):
        if self.openssl_name:
            return True
        else:
            return False

    @property
    def tls10_cipher(self):
        if 'tls1.0' in self.tls_version.lower():
            return True
        else:
            return False

    @property
    def tls12_cipher(self):
        if 'tls1.2' in self.tls_version.lower():
            return True
        else:
            return False


    objects = models.Manager()
    custom_filters = CipherSuiteQuerySet.as_manager()

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

    objects = models.Manager()
    custom_filters = RfcQuerySet.as_manager()

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

    def __lt__(self, other):
        return True if self.short_name < other.short_name else False

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
        help_text="For reference, see https://getbootstrap.com/docs/3.3/components#glyphicons"
    )

    def __str__(self):
        return self.title
