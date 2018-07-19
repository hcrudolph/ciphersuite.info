from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Q
from directory.models import CipherSuite, Rfc, Technology


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
    if version == "tls10":
        return cipher_suites.filter(tls_version__icontains='tls1.0')
    elif version == "tls12":
        return cipher_suites.filter(tls_version__icontains='tls1.2')
    else:
        return cipher_suites

def filter_cs_by_software(cipher_suites, software):
    if software == "gnutls":
        return cipher_suites.exclude(gnutls_name__iexact='')
    elif software == "openssl":
        return cipher_suites.exclude(openssl_name__iexact='')
    else:
        return cipher_suites

def sort_cipher_suites(cipher_suites, order):
    """Sorts the given list of CipherSuite instances in a specific order."""

    # maps GET sorting parameter to django ordering
    order_variants = {
        'auth-asc': 'auth_algorithm',
        'auth-desc': '-auth_algorithm',
        'enc-asc': 'enc_algorithm',
        'enc-desc': '-enc_algorithm',
        'hash-asc': 'hash_algorithm',
        'hash-desc': '-hash_algorithm',
        'kex-asc': 'kex_algorithm',
        'kex-desc': '-kex_algorithm',
        'name-asc': 'name',
        'name-desc': '-name',
    }

    try:
        csorder = order_variants[order]
    except KeyError:
        csorder = 'name' # default ordering

    return cipher_suites.order_by(csorder)

def sort_rfcs(rfcs, order):
    """Sorts the given list of Rfc instances in a specific order."""

    # maps GET sorting parameter to django ordering
    order_variants = {
        'number-asc': 'number',
        'number-desc': '-number',
        'title-asc': 'title',
        'title-desc': '-title',
    }

    try:
        rfcorder = order_variants[order]
    except KeyError:
        rfcorder = 'number' # default ordering

    return rfcs.order_by(rfcorder)

def search_rfcs(search_term):
    """Returns a QuerySet of all Rfc instances,
        whose title or number contains the given search term"""

    return Rfc.objects.filter(
        Q(title__icontains=search_term)|
        Q(number__icontains=search_term)
    )

def search_cipher_suites(search_term):
    """Returns a QuerySet of all CipherSuite instances, whose name, 
    algorithms or their vulnerabilities contain the given search term"""

    return CipherSuite.objects.filter(
        Q(name__icontains=search_term)|
        Q(openssl_name__icontains=search_term)|
        Q(gnutls_name__icontains=search_term)|
        Q(auth_algorithm__long_name__icontains=search_term)|
        Q(enc_algorithm__long_name__icontains=search_term)|
        Q(kex_algorithm__long_name__icontains=search_term)|
        Q(hash_algorithm__long_name__icontains=search_term)|
        Q(protocol_version__long_name__icontains=search_term)|
        Q(auth_algorithm__vulnerabilities__name__icontains=search_term)|
        Q(enc_algorithm__vulnerabilities__name__icontains=search_term)|
        Q(kex_algorithm__vulnerabilities__name__icontains=search_term)|
        Q(hash_algorithm__vulnerabilities__name__icontains=search_term)
    )

def filter_cipher_suites(cipher_suite_list, filter):
    """Returns a list of CipherSuite instances filtered by their algorithm's vulnerabilities."""

    if filter=='insecure':
        return cipher_suite_list.filter(
            Q(protocol_version__vulnerabilities__severity='HIG')|
            Q(kex_algorithm__vulnerabilities__severity='HIG')|
            Q(enc_algorithm__vulnerabilities__severity='HIG')|
            Q(auth_algorithm__vulnerabilities__severity='HIG')|
            Q(hash_algorithm__vulnerabilities__severity='HIG')
        )
    elif filter=='weak':
        return cipher_suite_list.filter(
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
    elif filter=='secure':
        return cipher_suite_list.exclude(
            Q(auth_algorithm__vulnerabilities__severity='HIG')|
            Q(auth_algorithm__vulnerabilities__severity='MED')|
            Q(enc_algorithm__vulnerabilities__severity='HIG')|
            Q(enc_algorithm__vulnerabilities__severity='MED')|
            Q(hash_algorithm__vulnerabilities__severity='HIG')|
            Q(hash_algorithm__vulnerabilities__severity='MED')|
            Q(kex_algorithm__vulnerabilities__severity='HIG')|
            Q(kex_algorithm__vulnerabilities__severity='MED')|
            Q(protocol_version__vulnerabilities__severity='HIG')|
            Q(protocol_version__vulnerabilities__severity='MED')
        )
    else:
        return cipher_suite_list
