from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.postgres.search import SearchVector
from django.db.models import Q
from django.template import loader
from django.shortcuts import get_object_or_404, render

from .models import *
from .forms import *
 
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


def index(request):
    """Site-wide index accessed when visiting the web root."""

    context = {
        'hide_navbar_search': True,
        'search_form': MainSearchForm(),
    }

    return render(request, 'directory/index.html', context)


def about(request):
    """Static page with project information."""

    about_page = get_object_or_404(StaticPage, pk='about')

    context = {
        'navbar_context': about_page.title,
        'search_form': NavbarSearchForm(),
        'static_page': about_page,
    }

    return render(request, 'directory/static_page.html', context)


def index_cs(request):
    """CipherSuite overview, listing all instances stored in the database."""

    def get_cipher_suites(filter):
        """Returns a (filtered) list of CipherSuite instances."""  
        if filter=='insecure':
            return CipherSuite.vulnerabilities.insecure()
        elif filter=='weak':
            return CipherSuite.vulnerabilities.weak()
        elif filter=='secure':
            return CipherSuite.vulnerabilities.secure()
        else:
            return CipherSuite.objects.all()

    def sort_cipher_suites(cs, order):
        """Sorts the given list of CipherSuite instances in a specific order."""
        if order=='name-desc':
            return cs.order_by('-name')
        elif order=='kex-asc':
            return cs.order_by('kex_algorithm')
        elif order=='kex-desc':
            return cs.order_by('-kex_algorithm')
        elif order=='auth-asc':
            return cs.order_by('auth_algorithm')
        elif order=='auth-desc':
            return cs.order_by('-auth_algorithm')
        elif order=='enc-asc':
            return cs.order_by('enc_algorithm')
        elif order=='enc-desc':
            return cs.order_by('-enc_algorithm')
        elif order=='hash-asc':
            return cs.order_by('hash_algorithm')
        elif order=='hash-desc':
            return cs.order_by('-hash_algorithm')
        else:
            return cs.order_by('name')

    # parse GET parameters
    sorting = request.GET.get('s', '')
    filter = request.GET.get('f', '')
    page = request.GET.get('p', 1)

    cipher_suite_list = sort_cipher_suites(get_cipher_suites(filter), sorting)
    cipher_suites_paginated = paginate(cipher_suite_list, page, 15)

    context = {
        'cipher_suites': cipher_suites_paginated,
        'filter': filter,
        'sorting': sorting,
        'navbar_context': 'cs',
        'page_number_range': range(1, cipher_suites_paginated.paginator.num_pages + 1),
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'directory/index_cs.html', context)


def index_rfc(request):
    """Rfc overview, listing all instances stored in the database."""

    def sort_rfcs(rfcs, order):
        """Sorts the given list of Rfc instances in a specific order."""
        if order=='number-asc':
            return rfcs.order_by('number')
        elif order=='number-desc':
            return rfcs.order_by('-number')
        elif order=='title-asc':
            return rfcs.order_by('title')
        elif order=='title-desc':
            return rfcs.order_by('-title')


    # parse GET parameters
    sorting = request.GET.get('s', 'number-asc')
    page = request.GET.get('p', 1)

    rfc_list = sort_rfcs(Rfc.objects.all(), sorting)
    rfc_list_paginated = paginate(rfc_list, page, 15)

    context = {
        'navbar_context': 'rfc',
        'page_number_range': range(1, rfc_list_paginated.paginator.num_pages + 1),
        'rfc_list_paginated': rfc_list_paginated,
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'directory/index_rfc.html', context)


def detail_cs(request, cs_name):
    """Detailed view of a CipherSuite instance."""

    # parse GET parameters
    prev_page = request.GET.get('prev', None)

    cipher_suite = get_object_or_404(CipherSuite, pk=cs_name)
    referring_rfc_list = cipher_suite.defining_rfcs.all()
    related_tech = [
        cipher_suite.protocol_version,
        cipher_suite.kex_algorithm,
        cipher_suite.auth_algorithm,
        cipher_suite.enc_algorithm,
        cipher_suite.hash_algorithm,
    ]

    context = {
        'cipher_suite': cipher_suite,
        'prev_page': prev_page,
        'referring_rfc_list': referring_rfc_list,
        'related_tech': related_tech,
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'directory/detail_cs.html', context)


def detail_rfc(request, rfc_number):
    """Detailed view of an Rfc instance."""

    # parse GET parameters
    prev_page = request.GET.get('prev', None)

    rfc = get_object_or_404(Rfc, pk=rfc_number)
    all_rfc_status_codes = {
        'BCP': 'Best Current Practise',
        'DST': 'Draft Standard',
        'EXP': 'Experimental',
        'HST': 'Historic',
        'INF': 'Informational',
        'IST': 'Internet Standard',
        'PST': 'Proposed Standard',
        'UND': 'Undefined',
    }
    rfc_status_code = all_rfc_status_codes[rfc.status]
    defined_cipher_suites = rfc.defined_cipher_suites.all()
    related_docs = rfc.related_documents.all()

    context = {
        'defined_cipher_suites': defined_cipher_suites,
        'prev_page': prev_page,
        'related_docs': related_docs,
        'rfc': rfc,
        'rfc_status_code': rfc_status_code,
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'directory/detail_rfc.html', context)


def search(request):
    """Search functionality and result page for Rfc and CipherSuite instances."""

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

    # parse GET parameters
    search_term = request.GET.get('q', '')
    filter = request.GET.get('f', '')
    category = request.GET.get('c', 'cs')
    page = request.GET.get('p', 1)

    result_list_cs = filter_cipher_suites(search_cipher_suites(search_term), filter)
    result_list_rfc = search_rfcs(search_term)

    # distinguish results to display by category
    if category=='cs':
        active_tab = 'cs'
        result_list = result_list_cs
    else:
        active_tab = 'rfc'
        result_list = result_list_rfc

    result_list_paginated = paginate(result_list, page, 15)

    context = {
        'active_tab': active_tab,
        'category': category,
        'filter': filter,
        'full_path' : request.get_full_path(),
        'page_number_range': range(1, result_list_paginated.paginator.num_pages+1),
        'result_count_cs': len(result_list_cs),
        'result_count_rfc': len(result_list_rfc),
        'search_form': NavbarSearchForm(),
        'search_result_list': result_list_paginated,
        'search_term': search_term,
    }

    return render(request, 'directory/search.html', context)

