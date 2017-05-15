from django.db import models


class CipherSuite(models.Model):
    name = models.CharField(
        primary_key=True,
        max_length=200,
    )
    # protocol version (SSL, TLS, etc.)
    protocol_version = models.ForeignKey(
        'ProtocolVersion',
        verbose_name='Protocol',
        editable=False,
    )
    # key exchange algorithm
    kex_algorithm = models.ForeignKey(
        'KexAlgorithm',
        verbose_name='Key exchange algorithm',
        editable=False,
    )
    # encryption algorithm
    enc_algorithm = models.ForeignKey(
        'EncAlgorithm',
        verbose_name='Encryption algorithm',
        editable=False,
    )
    # message authentication code algorithm
    mac_algorithm = models.ForeignKey(
        'MacAlgorithm',
        verbose_name='MAC algorithm',
        editable=False,
    )

    def save(self):
        # derive related algorithms form self.name
        (prt,_,rest) = self.name.replace("_", " ").partition(" ")
        (kex,_,rest) = rest.partition("WITH")
        (enc,_,mac) = rest.rpartition(" ")

        self.protocol_version, _ = ProtocolVersion.objects.get_or_create(
            short_name=prt.strip()
        )
        self.kex_algorithm, _ = KexAlgorithm.objects.get_or_create(
            short_name=kex.strip()
        )
        self.enc_algorithm, _ = EncAlgorithm.objects.get_or_create(
            short_name=enc.strip()
        )
        self.mac_algorithm, _ = MacAlgorithm.objects.get_or_create(
            short_name=mac.strip()
        )

        super(CipherSuite, self).save()

    def __str__(self):
        return self.name


class Rfc(models.Model):
    # predefined choices for document status
    STD_IN='Internet Standard'
    STD_PR='Proposed Standard'
    STD_DF='Draft Standard'
    BCP='Best Current Practise'
    INF='Informational'
    EXP='Experimental'
    HST='Historic'
    STATUS_CHOICES = (
        (STD_IN, 'Internet Standard'),
        (STD_PR, 'Proposed Standard'),
        (STD_DF, 'Draft Standard'),
        (BCP, 'Best Current Practise'),
        (INF, 'Informational'),
        (EXP, 'Experimental'),
        (HST, 'Historic'),
    )
    number = models.DecimalField(
        primary_key=True,
        max_digits=5,
        decimal_places=0,
    )
    status = models.CharField(
        max_length=25,
        choices=STATUS_CHOICES,
    )
    title = models.CharField(
        max_length=250,
    )
    release_year = models.DecimalField(
        max_digits=4,
        decimal_places=0,
    )
    defined_cipher_suites = models.ManyToManyField(
        'CipherSuite',
        verbose_name='Defined cipher suites',
        related_name='defining_rfcs',
        blank=True,
    )
    related_documents = models.ManyToManyField(
        'self',
        verbose_name='Related RFCs',
        blank=True,
    )

    def __str__(self):
        return "RFC {}".format(self.number)


class ProtocolVersion(models.Model):
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


class KexAlgorithm(models.Model):
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


class EncAlgorithm(models.Model):
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


class MacAlgorithm(models.Model):
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


class Vulnerability(models.Model):
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
