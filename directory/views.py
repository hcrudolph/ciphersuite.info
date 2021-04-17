from django.shortcuts import get_object_or_404, render, redirect
from django.db.models import Value, FloatField
from directory.helpers import *
from directory.models import *
from directory.forms import *


def index(request):
    """Site-wide index accessed when visiting the web root."""

    announcements = Announcement.objects.all()

    context = {
        'hide_navbar_search': True,
        'search_form': MainSearchForm(),
        'announcements': announcements,
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
    sorting = request.GET.get('sort', 'name-asc')
    sec_level = request.GET.get('security', 'all')
    tls_version = request.GET.get('tls', 'all')
    software = request.GET.get('software', 'all')
    single_page = request.GET.get('singlepage', 'false')
    page = request.GET.get('page', '1')

    # get subsets based on list filters
    cs_by_sl = get_cs_by_security_level(sec_level)
    cs_by_sw = get_cs_by_software(software)
    cs_by_tv = get_cs_by_tls_version(tls_version)

    # create intersection of all subsets
    cipher_suites = cs_by_sl.intersection(cs_by_sw, cs_by_tv)

    if len(cipher_suites) > 0:
        cipher_suites = sort_cipher_suites(cipher_suites, sorting)

    # paginate depending on GET parameter
    if single_page == 'true' and len(cipher_suites) > 0:
        cipher_suites_paginated = paginate(
            cipher_suites, page, len(cipher_suites))
    else:
        cipher_suites_paginated = paginate(
            cipher_suites, page, 15)

    # display CS name format according to search query
    search_type = 'openssl' if software == 'openssl' else 'iana'

    context = {
        'count': cipher_suites_paginated.paginator.count,
        'navbar_context': 'cs',
        'page_number_range': cipher_suites_paginated.paginator.page_range,
        'results': cipher_suites_paginated,
        'search_form': NavbarSearchForm(),
        'search_type': search_type,
        'sec_level': sec_level,
        'singlepage': single_page,
        'software': software,
        'sorting': sorting,
        'tls_version': tls_version,
    }

    return render(request, 'directory/index_cs.html', context)


def index_rfc(request):
    """Rfc overview, listing all instances stored in the database."""

    # parse GET parameters
    sorting = request.GET.get('sorting', 'number-asc').strip()
    single_page = request.GET.get('singlepage', 'false').strip()
    page = request.GET.get('page', '1').strip()

    # sort result list
    rfc_list = sort_rfcs(Rfc.objects.all(), sorting)

    # paginate result list depending on GET parameter
    if single_page == 'true':
        rfc_list_paginated = paginate(rfc_list, page, len(rfc_list))
    else:
        rfc_list_paginated = paginate(rfc_list, page, 15)

    context = {
        'navbar_context': 'rfc',
        'page_number_range': rfc_list_paginated.paginator.page_range,
        'results': rfc_list_paginated,
        'search_form': NavbarSearchForm(),
        'singlepage': single_page,
    }

    return render(request, 'directory/index_rfc.html', context)


def detail_cs(request, cs_name):
    """Detailed view of a CipherSuite instance."""

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
        'referring_rfc_list': referring_rfc_list,
        'related_tech': related_tech,
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'directory/detail_cs.html', context)


def detail_rfc(request, rfc_number):
    """Detailed view of an Rfc instance."""

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
        'related_docs': related_docs,
        'rfc_status_code': rfc_status_code,
        'rfc': rfc,
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'directory/detail_rfc.html', context)


def search(request):
    """Search functionality and result page for Rfc and CipherSuite instances."""

    # parse GET parameters
    search_term = request.GET.get('q', '')
    sec_level = request.GET.get('security', 'all')
    sorting = request.GET.get('sort', 'rel')
    tls_version = request.GET.get('tls', 'all')
    software = request.GET.get('software', 'all')
    single_page = request.GET.get('singlepage', 'false')
    category = request.GET.get('cat', 'cs')
    page = request.GET.get('page', '1')

    # display cs name format according to search query
    search_type = 'openssl' if ('-' in search_term) or (software == 'openssl') else 'iana'

    # get subsets based on search term
    ranked_list = search_cipher_suites(search_term)
    search_result = CipherSuite.objects.filter(pk__in=ranked_list.values_list('name', flat=True))

    # get subsets based on list filters
    cs_by_sl = get_cs_by_security_level(sec_level)
    cs_by_sw = get_cs_by_software(software)
    cs_by_tv = get_cs_by_tls_version(tls_version)

    # create intersection of all subsets
    cipher_suites = search_result.intersection(cs_by_sl, cs_by_sw, cs_by_tv)
    rfcs = search_rfcs(search_term)

    # Query list returned from db is already sorted by relevancy
    result_list_cs = sort_cipher_suites(cipher_suites, sorting)
    result_list_rfc = sort_rfcs(rfcs, sorting)

    # distinguish results to display by category
    if category == 'cs':
        cs_tab_active = True
        result_list = result_list_cs
    else:
        cs_tab_active = False
        result_list = result_list_rfc

    # paginate depending on GET parameter
    if single_page == 'true' and len(result_list) > 0:
        result_list_paginated = paginate(result_list, page, len(result_list))
    else:
        result_list_paginated = paginate(result_list, page, 15)

    context = {
        'category': category,
        'cs_tab_active': cs_tab_active,
        'page_number_range': result_list_paginated.paginator.page_range,
        'result_count_cs': result_list_cs.count,
        'result_count_rfc': result_list_rfc.count,
        'results': result_list_paginated,
        'search_form': NavbarSearchForm(),
        'search_term': search_term,
        'search_type': search_type,
        'sec_level': sec_level,
        'singlepage': single_page,
        'software': software,
        'sorting': sorting,
        'tls_version': tls_version,
    }

    return render(request, 'directory/search.html', context)