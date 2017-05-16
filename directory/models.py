from django.db import models


class CipherSuite(models.Model):
    class Meta:
        verbose_name='cipher suite'
        verbose_name_plural='cipher suites'
        ordering=['name']

    name = models.CharField(
        primary_key=True,
        max_length=200,
    )
    # protocol version (SSL, TLS, etc.)
    protocol_version = models.ForeignKey(
        'ProtocolVersion',
        verbose_name='protocol',
        editable=False,
    )
    # key exchange algorithm
    kex_algorithm = models.ForeignKey(
        'KexAlgorithm',
        verbose_name='key exchange algorithm',
        editable=False,
    )
    # encryption algorithm
    enc_algorithm = models.ForeignKey(
        'EncAlgorithm',
        verbose_name='encryption algorithm',
        editable=False,
    )
    # message authentication code algorithm
    hash_algorithm = models.ForeignKey(
        'HashAlgorithm',
        verbose_name='hash algorithm',
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
    STATUS_CHOICES = (
        ('STD_IN', 'Internet Standard'),
        ('STD_PR', 'Proposed Standard'),
        ('STD_DF', 'Draft Standard'),
        ('BCP', 'Best Current Practise'),
        ('INF', 'Informational'),
        ('EXP', 'Experimental'),
        ('HST', 'Historic'),
    )
    status = models.CharField(
        max_length=25,
        choices=STATUS_CHOICES,
    )
    title = models.CharField(
        max_length=250,
    )
    release_year = models.IntegerField()
    defined_cipher_suites = models.ManyToManyField(
        'CipherSuite',
        verbose_name='defined cipher suites',
        related_name='defining_rfcs',
        blank=True,
    )
    related_documents = models.ManyToManyField(
        'self',
        verbose_name='related RFCs',
        blank=True,
    )

    def __str__(self):
        return "RFC {}".format(self.number)


class Technology(models.Model):
    class Meta:
        abstract=True
        ordering=['short_name']
        verbose_name_plural='Technologies',

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
    class Meta:
        verbose_name='protocol version'
        verbose_name_plural='protocol versions'


class KexAlgorithm(Technology):
    class Meta:
        verbose_name='key exchange algorithm'
        verbose_name_plural='key exchange algorithms'


class EncAlgorithm(Technology):
    class Meta:
        verbose_name='encryption algorithm'
        verbose_name_plural='encryption algorithms'


class HashAlgorithm(Technology):
    class Meta:
        verbose_name='hash algorithm'
        verbose_name_plural='hash algorithms'


class Vulnerability(models.Model):
    class Meta:
        verbose_name='vulnerability'
        verbose_name_plural='vulnerabilities'

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
    cvss_score = models.DecimalField(
        max_digits=3,
        decimal_places=1,
        blank=True,
    )

    def __str__(self):
        return self.name

