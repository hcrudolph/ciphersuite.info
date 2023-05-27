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

def filter_ciphersuites(ciphersuites, sec, tls, lib):
    """Wrapper function for filter_cs_sec, filter_cs_tls, filter_cs_lib."""
    ciphersuites = filter_cs_sec(ciphersuites, sec)
    ciphersuites = filter_cs_tls(ciphersuites, tls)
    ciphersuites = filter_cs_lib(ciphersuites, lib)
    return ciphersuites


def filter_cs_sec(ciphersuites, security_level):
    """Filters the given list of ciphersuites by a specified security_level."""

    if security_level == 'recommended':
        return ciphersuites.filter(security=0)
    elif security_level == 'secure':
        return ciphersuites.filter(security=1)
    elif security_level == 'weak':
        return ciphersuites.filter(security=2)
    elif security_level == 'insecure':
        return ciphersuites.filter(security=3)
    else:
        return ciphersuites


def filter_cs_tls(ciphersuites, tls_version):
    """Filters the given list of ciphersuites by a specified tls_version."""

    if tls_version == 'tls10':
        return ciphersuites.filter(tls_version__major=1, tls_version__minor=0)
    elif tls_version == 'tls11':
        return ciphersuites.filter(tls_version__major=1, tls_version__minor=1)
    elif tls_version == 'tls12':
        return ciphersuites.filter(tls_version__major=1, tls_version__minor=2)
    elif tls_version == 'tls13':
        return ciphersuites.filter(tls_version__major=1, tls_version__minor=3)
    else:
        return ciphersuites


def filter_cs_lib(ciphersuites, software_library):
    """Filters the given list of ciphersuites by a specified software_library."""

    if software_library == 'gnutls':
        return ciphersuites.filter(openssl_name__isnull=False)
    elif software_library == 'gnutls':
        return ciphersuites.filter(gnutls_name__isnull=False)
    else:
        return ciphersuites


def sort_ciphersuites(ciphersuites, order):
    """Sorts the given list of ciphersuites in a specified order."""

    if order == 'name-asc':
        return ciphersuites.order_by('name')
    elif order == 'name-desc':
        return ciphersuites.order_by('-name')
    else:
        return ciphersuites


def sort_rfcs(rfcs, order):
    """Sorts the given list of rfcs instances in a specified order."""

    if order == 'number-asc':
        return rfcs.order_by('number')
    elif order == 'number-desc':
        return rfcs.order_by('-number')
    elif order == 'title-asc':
        return rfcs.order_by('title')
    elif order == 'title-desc':
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
