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
        return CipherSuite.custom_filters.recommended()
    elif sec_level == 'secure':
        return CipherSuite.custom_filters.secure()
    elif sec_level == 'weak':
        return CipherSuite.custom_filters.weak()
    elif sec_level == 'insecure':
        return CipherSuite.custom_filters.insecure()
    else:
        return CipherSuite.objects.all()

def filter_cs_by_tls_version(cipher_suites, version):
    """Returns a list of CipherSuite instances filtered by their TLS version."""

    if version == "tls10":
        return cipher_suites.filter(tls_version__short='11')
    elif version == "tls12":
        return cipher_suites.filter(tls_version__short='12')
    elif version == "tls13":
        return cipher_suites.filter(tls_version__short='13')
    else:
        return cipher_suites

def filter_cs_by_software(cipher_suites, software):
    """Returns a list of CipherSuite instances filtered by their available implementations."""

    if software == "gnutls":
        return cipher_suites.exclude(gnutls_name='')
    elif software == "openssl":
        return cipher_suites.exclude(openssl_name='')
    else:
        return cipher_suites

def filter_cs_by_sec_level(cipher_suites, sec_level):
    """Returns a list of CipherSuite instances filtered by their algorithm's vulnerabilities."""

    if sec_level == 'insecure':
        return cipher_suites.intersection(CipherSuite.custom_filters.insecure())
    elif sec_level == 'weak':
        return cipher_suites.intersection(CipherSuite.custom_filters.weak())
    elif sec_level == 'secure':
        return cipher_suites.intersection(CipherSuite.custom_filters.secure())
    elif sec_level == 'recommended':
        return cipher_suites.intersection(CipherSuite.custom_filters.recommended())
    else:
        return cipher_suites

def sort_cipher_suites(cipher_suites, ordering):
    """Sorts the given list of CipherSuite instances in a specific order."""

    if ordering == 'auth-asc':
        return cipher_suites.order_by('auth_algorithm')
    elif ordering == 'auth-desc':
        return cipher_suites.order_by('-auth_algorithm')
    elif ordering == 'enc-asc':
        return cipher_suites.order_by('enc_algorithm')
    elif ordering == 'enc-desc':
        return cipher_suites.order_by('-enc_algorithm')
    elif ordering == 'hash-asc':
        return cipher_suites.order_by('hash_algorithm')
    elif ordering == 'hash-desc':
        return cipher_suites.order_by('-hash_algorithm')
    elif ordering == 'kex-asc':
        return cipher_suites.order_by('kex_algorithm')
    elif ordering == 'kex-desc':
        return cipher_suites.order_by('-kex_algorithm')
    elif ordering == 'name-asc':
        return cipher_suites.order_by('name')
    elif ordering == 'name-desc':
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
