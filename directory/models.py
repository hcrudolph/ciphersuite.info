from django.db import models

class CipherSuite(models.Model):
    name = models.CharField(
        primary_key=True,
        max_length=200,
    )
    kex = models.CharField(
        verbose_name='Key exchange algorithm',
        max_length=20,
    )
    # encryption algorithm
    enc = models.CharField(
        verbose_name='Encryption algorithm',
        max_length=20,
    )
    # message authentication code algorithm
    mac = models.CharField(
        verbose_name='MAC algorithm',
        max_length=20,
    )
    # # pseudorandom function
    # prf = models.CharField(
    #     verbose_name='Pseudorandom function',
    #     max_length=20,
    # )
    # RFCs that include this cipher suite
    rfcs = models.ManyToManyField(
        'Rfc',
        verbose_name='Referring RFC',
        blank=True,
    )

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
    title = models.CharField(max_length=250)
    # year of release
    year = models.DecimalField(max_digits=4, decimal_places=0)
    # defined cipher suites
    cipher_suites = models.ManyToManyField(
        'CipherSuite',
        verbose_name='Defined cipher suites',
        blank=True,
    )
    obsoleted_by = models.ForeignKey(
        'self',
        related_name='obsoleted_set',
        null=True,
        blank=True,
        default=None,
    )
    obsoletes = models.ForeignKey(
        'self',
        related_name='obsoleting_set',
        null=True,
        blank=True,
        default=None,
    )

    def __str__(self):
        return "RFC {}".format(self.number)

