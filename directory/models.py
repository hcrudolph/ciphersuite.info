from django.utils.translation import gettext_lazy as _
from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector
from django.db.models.fields.related import ManyToManyField
from django.db import models
from django.db.models import Q
from markdownx.models import MarkdownxField
from markdownx.utils import markdownify


class PrintableModel(models.Model):
    def to_dict(self):
        opts = self._meta
        data = {}
        for f in opts.concrete_fields + opts.many_to_many:
            if isinstance(f, ManyToManyField):
                if self.pk is None:
                    data[f.name] = []
                else:
                    data[f.name] = [x.__str__() for x in list(f.value_from_object(self))]
            else:
                data[f.name] = f.value_from_object(self)
        return data

    class Meta:
        abstract = True


class CipherSuiteQuerySet(models.QuerySet):
    def recommended(self):
        return self.filter(
            ~(
                Q(protocol_version__vulnerabilities__severity__gte=0)|
                Q(kex_algorithm__vulnerabilities__severity__gte=0)|
                Q(enc_algorithm__vulnerabilities__severity__gte=0)|
                Q(auth_algorithm__vulnerabilities__severity__gte=0)|
                Q(hash_algorithm__vulnerabilities__severity__gte=0)|
                Q(enc_algorithm__short_name__icontains="CCM")
            ) & (
                Q(kex_algorithm__short_name__icontains='DHE')|
                Q(tls_version__short='13')
            )
        ).distinct()

    def secure(self):
        return self.exclude(
            Q(protocol_version__vulnerabilities__severity__gt=0)|
            Q(kex_algorithm__vulnerabilities__severity__gt=0)|
            Q(enc_algorithm__vulnerabilities__severity__gt=0)|
            Q(auth_algorithm__vulnerabilities__severity__gt=0)|
            Q(hash_algorithm__vulnerabilities__severity__gt=0)
        ).distinct().difference(
            self.recommended()
        )

    def weak(self):
        return self.filter(
            Q(protocol_version__vulnerabilities__severity=1)|
            Q(kex_algorithm__vulnerabilities__severity=1)|
            Q(enc_algorithm__vulnerabilities__severity=1)|
            Q(auth_algorithm__vulnerabilities__severity=1)|
            Q(hash_algorithm__vulnerabilities__severity=1)
        ).distinct().difference(
            self.insecure()
        )

    def insecure(self):
        return self.filter(
            Q(protocol_version__vulnerabilities__severity=2)|
            Q(kex_algorithm__vulnerabilities__severity=2)|
            Q(enc_algorithm__vulnerabilities__severity=2)|
            Q(auth_algorithm__vulnerabilities__severity=2)|
            Q(hash_algorithm__vulnerabilities__severity=2)
        ).distinct()

    def search(self, search_term):
        # create query and vector object needed for ranking results
        query = SearchQuery(search_term)
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

        # retrieve list of all results ordered by decreasing relevancy
        ranked_results = CipherSuite.objects.annotate(
            rank=SearchRank(vector, query)
        ).order_by('-rank')

        # exclude items that do not match query at all
        return ranked_results.exclude(
            ~(
                Q(name__icontains=search_term)|
                Q(openssl_name__icontains=search_term)|
                Q(gnutls_name__icontains=search_term)|
                Q(auth_algorithm__long_name__icontains=search_term)|
                Q(enc_algorithm__long_name__icontains=search_term)|
                Q(kex_algorithm__long_name__icontains=search_term)|
                Q(hash_algorithm__long_name__icontains=search_term)|
                Q(protocol_version__vulnerabilities__name__icontains=search_term)|
                Q(auth_algorithm__vulnerabilities__name__icontains=search_term)|
                Q(enc_algorithm__vulnerabilities__name__icontains=search_term)|
                Q(kex_algorithm__vulnerabilities__name__icontains=search_term)|
                Q(hash_algorithm__vulnerabilities__name__icontains=search_term)|
                Q(protocol_version__vulnerabilities__description__icontains=search_term)|
                Q(auth_algorithm__vulnerabilities__description__icontains=search_term)|
                Q(enc_algorithm__vulnerabilities__description__icontains=search_term)|
                Q(kex_algorithm__vulnerabilities__description__icontains=search_term)|
                Q(hash_algorithm__vulnerabilities__description__icontains=search_term)
            )
        ).distinct()


class RfcQuerySet(models.QuerySet):
    def search(self, search_term):
        return self.filter(
            Q(title__icontains=search_term)|
            Q(number__icontains=search_term)
        ).distinct()


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


class CipherSuite(PrintableModel):
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
        db_index=True,
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
    tls_version = models.ManyToManyField(
        'TlsVersion',
        verbose_name=_('TLS version'),
        blank=True,
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
    # security level
    REC = 0
    SEC = 1
    WEK = 2
    INS = 3
    SECURITY_CHOICES = (
        (REC, 'recommended'),
        (SEC, 'secure'),
        (WEK, 'weak'),
        (INS, 'insecure')
    )
    security = models.IntegerField(
        verbose_name=_('security level'),
        choices=SECURITY_CHOICES,
        default=3,
        blank=True,
        editable=True,
    )

    @property
    def recommended(self):
        if self.security == 0:
            return True

    @property
    def secure(self):
        if self.security == 1:
            return True

    @property
    def weak(self):
        if self.security == 2:
            return True

    @property
    def insecure(self):
        if self.security == 3:
            return True

    @property
    def gnutls_cipher(self):
        if self.gnutls_name:
            return True

    @property
    def openssl_cipher(self):
        if self.openssl_name:
            return True

    @property
    def tls10_cipher(self):
        v0 = TlsVersion.objects.get(major=1, minor=0)
        v1 = TlsVersion.objects.get(major=1, minor=1)
        if v0 in self.tls_version.all() or \
           v1 in self.tls_version.all():
            return True

    @property
    def tls12_cipher(self):
        v = TlsVersion.objects.get(major=1, minor=2)
        if v in self.tls_version.all():
            return True

    @property
    def tls13_cipher(self):
        v = TlsVersion.objects.get(major=1, minor=3)
        if v in self.tls_version.all():
            return True

    objects = models.Manager()
    custom_filters = CipherSuiteQuerySet.as_manager()

    def __str__(self):
        return self.name


class Rfc(PrintableModel):
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


class TlsVersion(models.Model):
    class Meta:
        verbose_name=_('TLS version')
        verbose_name_plural=_('TLS versions')
        unique_together=(('major', 'minor'),)
        ordering=['major', 'minor']

    major = models.IntegerField()
    minor = models.IntegerField()
    short = models.CharField(
        max_length=3,
        editable=False,
        blank=True
    )

    def __str__(self):
        return f"TLS{self.major}.{self.minor}"


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

    pfs_support = models.BooleanField(
        default=False,
        null=True
    )


class AuthAlgorithm(Technology):
    class Meta(Technology.Meta):
        verbose_name=_('authentication algorithm')
        verbose_name_plural=_('authentication algorithms')


class EncAlgorithm(Technology):
    class Meta(Technology.Meta):
        verbose_name=_('encryption algorithm')
        verbose_name_plural=_('encryption algorithms')

    aead_algorithm = models.BooleanField(
        default=False,
        null=True
    )


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
    description = MarkdownxField(
        max_length=1000,
        blank=True,
    )

    SEVERITY_CHOICES = (
        (2, 'High'),
        (1, 'Medium'),
        (0, 'Low'),
    )
    severity = models.IntegerField(
        choices=SEVERITY_CHOICES,
        default=0,
    )

    @property
    def formatted_desc(self):
        return markdownify(self.description)

    def __str__(self):
        return self.name


class StaticPage(models.Model):
    class Meta:
        ordering=['rank']
        verbose_name=_('static page')
        verbose_name_plural=_('static pages')

    title = models.CharField(
        max_length=50,
        unique=True
    )
    content = MarkdownxField(
        max_length = 10000,
    )
    icon = models.CharField(
        max_length=50,
        help_text="For reference, see https://icons.getbootstrap.com/"
    )
    rank = models.IntegerField(
        help_text="Defines display order of static pages"
    )
    show_in_nav = models.BooleanField(
        default=True
    )
    direct_link = models.BooleanField(
        default=False
    )

    @property
    def formatted_content(self):
        return markdownify(self.content)

    def __str__(self):
        return self.title


class Announcement(models.Model):
    class Meta:
        ordering=['rank']

    SEVERITY_OPTIONS = (
        ('info', 'Info'),
        ('success', 'Success'),
        ('warning', 'Warning'),
        ('danger', 'Danger'),
    )

    rank = models.IntegerField(
        help_text="Defines display order of announcements"
    )
    text = models.CharField(
        max_length=250,
    )
    severity = models.CharField(
        max_length=10,
        choices=SEVERITY_OPTIONS
    )
    dismissable = models.BooleanField(
        default=False,
    )
    emoji = models.CharField(
        max_length=50,
        blank=True,
        help_text="For reference, see https://emoji-css.afeld.me/"
    )

    def __str__(self):
        return self.text[0:30] + "..."

class Sponsor(models.Model):
    title = models.CharField(
        max_length=50,
    )
    icon = models.ImageField(
        upload_to='sponsors/',
    )
    link = models.URLField()

    def __str__(self):
        return self.title