from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.shortcuts import get_object_or_404, render
from django.contrib.postgres.search import SearchVector
from django.db.models import Q

from .models import *
from .forms import *


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


def news(request):
    """Static page with project information."""

    news_page = get_object_or_404(StaticPage, pk='news')

    context = {
        'navbar_context': news_page.title,
        'search_form': NavbarSearchForm(),
        'static_page': news_page,
    }

    return render(request, 'directory/static_page.html', context)


def index_cs(request):
    """CipherSuite overview, listing all instances in ascending order by hexcode."""

    # parse GET parameters
    sorting = request.GET.get('s', 'name-asc')
    filtering = request.GET.get('f', '')
    page = request.GET.get('p', 1)

    if filtering=='insecure':
        cipher_suite_list = CipherSuite.vulnerabilities.insecure()
    elif filtering=='weak':
        cipher_suite_list = CipherSuite.vulnerabilities.weak()
    elif filtering=='secure':
        cipher_suite_list = CipherSuite.vulnerabilities.secure()
    else:
        cipher_suite_list = CipherSuite.objects.all()

    if sorting=='name-asc':
        cipher_suite_list = cipher_suite_list.order_by('name')
    elif sorting=='name-desc':
        cipher_suite_list = cipher_suite_list.order_by('-name')
    elif sorting=='kex-asc':
        cipher_suite_list = cipher_suite_list.order_by('kex_algorithm')
    elif sorting=='kex-desc':
        cipher_suite_list = cipher_suite_list.order_by('-kex_algorithm')
    elif sorting=='auth-asc':
        cipher_suite_list = cipher_suite_list.order_by('auth_algorithm')
    elif sorting=='auth-desc':
        cipher_suite_list = cipher_suite_list.order_by('-auth_algorithm')
    elif sorting=='enc-asc':
        cipher_suite_list = cipher_suite_list.order_by('enc_algorithm')
    elif sorting=='enc-desc':
        cipher_suite_list = cipher_suite_list.order_by('-enc_algorithm')
    elif sorting=='hash-asc':
        cipher_suite_list = cipher_suite_list.order_by('hash_algorithm')
    elif sorting=='hash-desc':
        cipher_suite_list = cipher_suite_list.order_by('-hash_algorithm')

    paginator = Paginator(cipher_suite_list, 15)

    try:
        cipher_suites = paginator.page(page)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        cipher_suites = paginator.page(1)
    except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        cipher_suites = paginator.page(paginator.num_pages)

    context = {
        'cipher_suites': cipher_suites,
        'filtering': filtering,
        'navbar_context': 'cs',
        'page_number_range': range(1, cipher_suites.paginator.num_pages + 1),
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'directory/index_cs.html', context)


def index_rfc(request):
    """Rfc overview, listing all instances in ascending order by number."""

    # parse GET parameters
    sorting = request.GET.get('s', 'number-asc')
    page = request.GET.get('p', 1)

    if sorting=='number-asc':
        rfc_list = Rfc.objects.order_by('number')
    elif sorting=='number-desc':
        rfc_list = Rfc.objects.order_by('-number')
    elif sorting=='title-asc':
        rfc_list = Rfc.objects.order_by('title')
    elif sorting=='title-desc':
        rfc_list = Rfc.objects.order_by('-title')

    paginator = Paginator(rfc_list, 15)

    try:
        rfc_list_paginated = paginator.page(page)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        rfc_list_paginated = paginator.page(1)
    except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        rfc_list_paginated = paginator.page(paginator.num_pages)

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
    """Search result page."""

    # parse GET parameters
    search_term = request.GET.get('q', '')
    filtering = request.GET.get('f', '')
    category = request.GET.get('c', 'cs')
    page = request.GET.get('p', 1)

    results_cs = CipherSuite.objects.filter(
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

    if filtering=='insecure':
        results_cs = results_cs.filter(
            Q(protocol_version__vulnerabilities__severity='HIG')|
            Q(kex_algorithm__vulnerabilities__severity='HIG')|
            Q(enc_algorithm__vulnerabilities__severity='HIG')|
            Q(auth_algorithm__vulnerabilities__severity='HIG')|
            Q(hash_algorithm__vulnerabilities__severity='HIG')
        )
    elif filtering=='weak':
        results_cs = results_cs.filter(
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
    elif filtering=='secure':
        results_cs = results_cs.exclude(
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

    results_rfc = Rfc.objects.filter(
        Q(title__icontains=search_term)|
        Q(number__icontains=search_term)
    )

    if category=='cs':
        active_tab = 'cs'
        results = results_cs
    else:
        active_tab = 'rfc'
        results = results_rfc

    paginator = Paginator(results, 15)
    try:
        results_paginated = paginator.page(page)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        results_paginated = paginator.page(1)
    except EmptyPage:
        # If page is out of range, deliver last page of results.
        results_paginated = paginator.page(paginator.num_pages)

    context = {
        'active_tab': active_tab,
        'category': category,
        'filtering': filtering,
        'full_path' : request.get_full_path(),
        'page_number_range': range(1, results_paginated.paginator.num_pages+1),
        'result_count_cs': len(results_cs),
        'result_count_rfc': len(results_rfc),
        'search_form': NavbarSearchForm(),
        'search_result_list': results_paginated,
        'search_term': search_term,
    }

    return render(request, 'directory/search.html', context)
