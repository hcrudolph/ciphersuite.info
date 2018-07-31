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
        return [cs for cs in cipher_suites if cs.tls10_cipher]
    elif version == "tls12":
        return [cs for cs in cipher_suites if cs.tls12_cipher]
    else:
        return cipher_suites

def filter_cs_by_software(cipher_suites, software):
    """Returns a list of CipherSuite instances filtered by their available implementations."""

    if software == "gnutls":
        return [cs for cs in cipher_suites if cs.gnutls_cipher]
    elif software == "openssl":
        return [cs for cs in cipher_suites if cs.openssl_cipher]
    else:
        return cipher_suites

def filter_cs_by_sec_level(cipher_suites, sec_level):
    """Returns a list of CipherSuite instances filtered by their algorithm's vulnerabilities."""

    if sec_level == 'insecure':
        return [cs for cs in cipher_suites if cs.insecure]
    elif sec_level == 'weak':
        return [cs for cs in cipher_suites if cs.weak]
    elif sec_level == 'secure':
        return [cs for cs in cipher_suites if cs.secure]
    elif sec_level == 'recommended':
        return [cs for cs in cipher_suites if cs.recommended]
    else:
        return cipher_suites

def sort_cipher_suites(cipher_suites, ordering):
    """Sorts the given list of CipherSuite instances in a specific order."""

    if ordering == 'auth-asc':
        return sorted(cipher_suites, key=lambda x: x.auth_algorithm)
    elif ordering == '-auth-desc':
        return sorted(cipher_suites, key=lambda x: x.auth_algorithm, reverse=True)
    elif ordering == 'enc-asc':
        return sorted(cipher_suites, key=lambda x: x.enc_algorithm)
    elif ordering == 'enc-desc':
        return sorted(cipher_suites, key=lambda x: x.enc_algorithm, reverse=True)
    elif ordering == 'hash-asc':
        return sorted(cipher_suites, key=lambda x: x.hash_algorithm)
    elif ordering == 'hash-desc':
        return sorted(cipher_suites, key=lambda x: x.hash_algorithm, reverse=True)
    elif ordering == 'kex-asc':
        return sorted(cipher_suites, key=lambda x: x.kex_algorithm)
    elif ordering == 'kex-desc':
        return sorted(cipher_suites, key=lambda x: x.kex_algorithm, reverse=True)
    elif ordering == 'name-desc':
        return sorted(cipher_suites, key=lambda x: x.name, reverse=True)
    else:
        return sorted(cipher_suites, key=lambda x: x.name)


def sort_rfcs(rfcs, ordering):
    """Sorts the given list of Rfc instances in a specific order."""

    if ordering == 'number-asc':
        return sorted(rfcs, key=lambda x: x.number)
    elif ordering == 'number-desc':
        return sorted(rfcs, key=lambda x: x.number, reverse=True)
    elif ordering == 'title-desc':
        return sorted(rfcs, key=lambda x: x.title, reverse=True)
    else:
        return sorted(rfcs, key=lambda x: x.title)


def search_rfcs(search_term):
    """Returns a QuerySet of all Rfc instances,
        whose title or number contains the given search term"""

    return Rfc.custom_filters.search(search_term)

def search_cipher_suites(search_term):
    """Returns a QuerySet of all CipherSuite instances, whose name, 
    algorithms or their vulnerabilities contain the given search term"""

    return CipherSuite.custom_filters.search(search_term)
