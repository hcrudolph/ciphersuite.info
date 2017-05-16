from django.http import HttpResponse
from django.template import loader
from django.shortcuts import get_object_or_404, render

from .models import *


def index_global(request):
    """Site-wide index accessed when visiting web root."""
    context = {
        'hide_nav_search': True,
    }
    return render(request, 'directory/index_global.html', context)


def about(request):
    """Static page with project information."""
    context = {
        'nav_active': 'about',
    }
    return render(request, 'directory/about.html', context)


def index_cs(request):
    """CipherSuite overview, listing all instances in ascending order by hexcode."""
    cipher_suite_list = CipherSuite.objects.order_by('name')
    context = {
        'cipher_suite_list': cipher_suite_list,
        'nav_active': 'cs',
    }
    return render(request, 'directory/index_cs.html', context)


def index_rfc(request):
    """Rfc overview, listing all instances in ascending order by number."""
    rfc_list = Rfc.objects.order_by('number')
    context = {
        'rfc_list': rfc_list,
        'nav_active': 'rfc',
    }
    return render(request, 'directory/index_rfc.html', context)


def detail_cs(request, cs_name):
    """Detailed view of a CipherSuite instance."""
    cipher_suite = get_object_or_404(CipherSuite, pk=cs_name)
    referring_rfc_list = cipher_suite.defining_rfcs.all()
    related_tech = [
        cipher_suite.protocol_version,
        cipher_suite.kex_algorithm,
        cipher_suite.enc_algorithm,
        cipher_suite.hash_algorithm,
    ]
    context = {
        'cipher_suite': cipher_suite,
        'referring_rfc_list': referring_rfc_list,
        'related_tech': related_tech,
    }
    return render(request, 'directory/detail_cs.html', context)


def detail_rfc(request, rfc_number):
    """Detailed view of an Rfc instance."""
    rfc = get_object_or_404(Rfc, pk=rfc_number)
    defined_cipher_suites = rfc.defined_cipher_suites.all()
    related_docs = rfc.related_documents.all()
    context = {
        'rfc': rfc,
        'defined_cipher_suites': defined_cipher_suites,
        'related_docs': related_docs,
    }
    return render(request, 'directory/detail_rfc.html', context)

