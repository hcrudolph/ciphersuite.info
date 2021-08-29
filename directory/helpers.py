from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from directory.models import CipherSuite, Rfc


def paginate(result_list, current_page, elements_per_page):
    """Generic function for paginating result lists."""

    paginator = Paginator(result_list, elements_per_page)
    try:
        result = paginator.page(current_page)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        result = paginator.page(1)
    except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        result = paginator.page(paginator.num_pages)
    return result

def get_cs_by_security_level(sec_level):
    """Returns all CipherSuites of a certain security level."""

    if sec_level == 'recommended':
        return CipherSuite.objects.filter(security=0)
    elif sec_level == 'secure':
        return CipherSuite.objects.filter(security__lte=1)
    elif sec_level == 'weak':
        return CipherSuite.objects.filter(security=2)
    elif sec_level == 'insecure':
        return CipherSuite.objects.filter(security=3)
    else:
        return CipherSuite.objects.all()

def get_cs_by_tls_version(version):
    """Returns a list of CipherSuite instances filtered by their TLS version."""

    if version == 'tls10':
        return CipherSuite.objects.filter(tls_version__short='11')
    elif version == 'tls12':
        return CipherSuite.objects.filter(tls_version__short='12')
    elif version == 'tls13':
        return CipherSuite.objects.filter(tls_version__short='13')
    else:
        return CipherSuite.objects.all()

def get_cs_by_software(software):
    """Returns a list of CipherSuite instances filtered by their available implementations."""

    if software == 'gnutls':
        return CipherSuite.objects.exclude(gnutls_name='')
    elif software == 'openssl':
        return CipherSuite.objects.exclude(openssl_name='')
    else:
        return CipherSuite.objects.all()

def filter_cs_by_sec_level(cipher_suites, sec_level):
    """Returns a list of CipherSuite instances filtered by their algorithm's vulnerabilities."""

    if sec_level == 'insecure':
        return cipher_suites.intersection(CipherSuite.objects.filter(security=3))
    elif sec_level == 'weak':
        return cipher_suites.intersection(CipherSuite.objects.filter(security=2))
    elif sec_level == 'secure':
        return cipher_suites.intersection(CipherSuite.objects.filter(security__lte=1))
    elif sec_level == 'recommended':
        return cipher_suites.intersection(CipherSuite.objects.filter(security=0))
    else:
        return cipher_suites

def sort_cipher_suites(cipher_suites, ordering):
    """Sorts the given list of CipherSuite instances in a specific order."""

    if ordering == 'asc':
        return cipher_suites.order_by('name')
    elif ordering == 'desc':
        return cipher_suites.order_by('-name')
    else:
        return cipher_suites


def sort_rfcs(rfcs, ordering):
    """Sorts the given list of Rfc instances in a specific order."""

    if ordering == 'number-asc':
        return rfcs.order_by('number')
    elif ordering == 'number-desc':
        return rfcs.order_by('-number')
    elif ordering == 'title-asc':
        return rfcs.order_by('title')
    elif ordering == 'title-desc':
        return rfcs.order_by('-title')
    else:
        return rfcs


def search_rfcs(search_term):
    """Returns a QuerySet of all Rfc instances,
        whose title or number contains the given search term"""

    return Rfc.custom_filters.search(search_term)

def search_cipher_suites(search_term):
    """Returns a QuerySet of all CipherSuite instances, whose name,
    algorithms or their vulnerabilities contain the given search term"""

    return CipherSuite.custom_filters.search(search_term)
