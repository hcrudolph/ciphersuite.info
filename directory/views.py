from django.shortcuts import get_object_or_404, render
from directory.helpers import *
from directory.models import *
from directory.forms import *
import re


def index(request):
    """Site-wide index accessed when visiting the web root."""

    announcements = Announcement.objects.all()
    sponsor = Sponsor.objects.first()

    context = {
        'hide_navbar_search': True,
        'search_form': MainSearchForm(),
        'announcements': announcements,
        'sponsor': sponsor,
    }
    return render(request, 'directory/index.html', context)


def static_page(request, sp_name):
    """Generic static page, to be created in admin interface."""

    # query result
    page = get_object_or_404(StaticPage, title__iexact=sp_name)
    sponsor = Sponsor.objects.first()

    context = {
        'navbar_context': page.title,
        'search_form': NavbarSearchForm(),
        'static_page': page,
        'sponsor': sponsor,
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

    ciphersuites = CipherSuite.objects.all()

    # Filtering
    ciphersuites = filter_ciphersuites(
        ciphersuites, sec_level, tls_version, software)

    # Sorting
    ciphersuites = sort_ciphersuites(ciphersuites, sorting)

    if len(ciphersuites) > 0:
        ciphersuites = sort_ciphersuites(ciphersuites, sorting)

    # paginate depending on GET parameter
    if single_page == 'true' and len(ciphersuites) > 0:
        ciphersuites_paginated = paginate(
            ciphersuites, page, len(ciphersuites))
    else:
        ciphersuites_paginated = paginate(
            ciphersuites, page, 15)

    sponsor = Sponsor.objects.first()

    context = {
        'count': ciphersuites_paginated.paginator.count,
        'navbar_context': 'cs',
        'page_number_range': ciphersuites_paginated.paginator.page_range,
        'results': ciphersuites_paginated,
        'search_form': NavbarSearchForm(),
        'sec_level': sec_level,
        'singlepage': single_page,
        'software': software,
        'sorting': sorting,
        'tls_version': tls_version,
        'sponsor': sponsor,
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

    sponsor = Sponsor.objects.first()

    context = {
        'navbar_context': 'rfc',
        'page_number_range': rfc_list_paginated.paginator.page_range,
        'results': rfc_list_paginated,
        'search_form': NavbarSearchForm(),
        'singlepage': single_page,
        'sponsor': sponsor,
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

    sponsor = Sponsor.objects.first()

    context = {
        'cipher_suite': cipher_suite,
        'referring_rfc_list': referring_rfc_list,
        'related_tech': related_tech,
        'search_form': NavbarSearchForm(),
        'sponsor': sponsor,
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
    sponsor = Sponsor.objects.first()

    context = {
        'defined_cipher_suites': defined_cipher_suites,
        'related_docs': related_docs,
        'rfc_status_code': rfc_status_code,
        'rfc': rfc,
        'search_form': NavbarSearchForm(),
        'sponsor': sponsor,
    }

    return render(request, 'directory/detail_rfc.html', context)


def search(request):
    """Search functionality and result page for Rfc and CipherSuite instances."""

    # parse GET parameters
    search_term = re.sub('[^A-Za-z0-9_-]+', '', request.GET.get('q', ''))
    sec_level = request.GET.get('security', 'all')
    sorting = request.GET.get('sort', 'rel')
    tls_version = request.GET.get('tls', 'all')
    software = request.GET.get('software', 'all')
    single_page = request.GET.get('singlepage', 'false')
    category = request.GET.get('cat', 'cs')
    page = request.GET.get('page', '1')

    # Searching
    ciphersuites = search_cipher_suites(search_term)
    rfcs = search_rfcs(search_term)

    # Filtering
    ciphersuites = filter_ciphersuites(
        ciphersuites, sec_level, tls_version, software)

    # Sorting
    result_list_cs = sort_ciphersuites(ciphersuites, sorting)
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

    sponsor = Sponsor.objects.first()

    context = {
        'category': category,
        'cs_tab_active': cs_tab_active,
        'page_number_range': result_list_paginated.paginator.page_range,
        'result_count_cs': result_list_cs.count,
        'result_count_rfc': result_list_rfc.count,
        'results': result_list_paginated,
        'search_form': NavbarSearchForm(),
        'search_term': search_term,
        'sec_level': sec_level,
        'singlepage': single_page,
        'software': software,
        'sorting': sorting,
        'tls_version': tls_version,
        'sponsor': sponsor,
    }

    return render(request, 'directory/search.html', context)