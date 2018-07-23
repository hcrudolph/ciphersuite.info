from django.shortcuts import get_object_or_404, render
from .helpers import *
from .models import *
from .forms import *


def index(request):
    """Site-wide index accessed when visiting the web root."""

    context = {
        'hide_navbar_search': True,
        'search_form': MainSearchForm(),
    }
    return render(request, 'directory/index.html', context)


def static_page(request, sp_name):
    """Generic static page, to be created in admin interface."""
    
    # query result
    page = get_object_or_404(StaticPage, pk=sp_name)
    
    context = {
        'navbar_context': page.title,
        'search_form': NavbarSearchForm(),
        'static_page': page,
    }
    return render(request, 'directory/static_page.html', context)


def index_cs(request):
    """CipherSuite overview, listing all instances stored in the database."""

    # parse GET parameters
    sorting = request.GET.get('sorting', 'name-asc').strip()
    sec_level = request.GET.get('sec_level', 'all').strip()
    tls_version = request.GET.get('tls_version', 'all').strip()
    software = request.GET.get('software', 'all').strip()
    page = request.GET.get('page', 1)

    # filter result list
    cipher_suites = filter_cs_by_software(
                        filter_cs_by_tls_version(
                            get_cs_by_security_level(sec_level), tls_version
                        ), software
                    )
    # sort result list
    sorted_cipher_suites = sort_cipher_suites(cipher_suites, sorting)
    # paginate result list
    cipher_suites_paginated = paginate(sorted_cipher_suites, page, 15)
    
    context = {
        'cipher_suites': cipher_suites_paginated,
        'count': len(sorted_cipher_suites),
        'navbar_context': 'cs',
        'page_number_range': range(1, cipher_suites_paginated.paginator.num_pages + 1),
        'search_form': NavbarSearchForm(),
        'sec_level': sec_level,
        'software': software,
        'sorting': sorting,
        'tls_version': tls_version,
    }
    return render(request, 'directory/index_cs.html', context)


def index_rfc(request):
    """Rfc overview, listing all instances stored in the database."""

    # parse GET parameters
    sorting = request.GET.get('sorting', 'number-asc').strip()
    page = request.GET.get('page', 1)

    # sort result list
    rfc_list = sort_rfcs(Rfc.objects.all(), sorting)
    # paginate result list
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

    # query result
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

    # query result
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
        'rfc_status_code': rfc_status_code,
        'rfc': rfc,
        'search_form': NavbarSearchForm(),
    }
    return render(request, 'directory/detail_rfc.html', context)


def search(request):
    """Search functionality and result page for Rfc and CipherSuite instances."""

    # parse GET parameters
    search_term = request.GET.get('q', '').strip()
    sec_level = request.GET.get('f', 'all').strip()
    category = request.GET.get('c', 'cs').strip()
    page = request.GET.get('page', 1)
    
    # display CS name format according to search term
    search_type = 'openssl' if '-' in search_term else 'iana'

    # filter result list
    result_list_cs = filter_cipher_suites(search_cipher_suites(search_term), sec_level)
    result_list_rfc = search_rfcs(search_term)

    # distinguish results to display by category
    if category=='cs':
        active_tab = 'cs'
        result_list = result_list_cs
    else:
        active_tab = 'rfc'
        result_list = result_list_rfc

    # paginate result list
    result_list_paginated = paginate(result_list, page, 15)

    context = {
        'active_tab': active_tab,
        'category': category,
        'filter': sec_level,
        'full_path' : request.get_full_path(),
        'page_number_range': range(1, result_list_paginated.paginator.num_pages+1),
        'result_count_cs': len(result_list_cs),
        'result_count_rfc': len(result_list_rfc),
        'search_form': NavbarSearchForm(),
        'search_result_list': result_list_paginated,
        'search_term': search_term,
        'search_type': search_type,
    }
    return render(request, 'directory/search.html', context)
