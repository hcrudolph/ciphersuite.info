from django.http import HttpResponse
from django.template import loader
from django.shortcuts import get_object_or_404, render

from .models import CipherSuite, Rfc


def index_global(request):
    return render(request, 'directory/index_global.html')

def index_cs(request):
    cipher_suite_list = CipherSuite.objects.order_by('name')
    context = {
        'cipher_suite_list': cipher_suite_list,
    }
    return render(request, 'directory/index_cs.html', context)

def index_rfc(request):
    rfc_list = Rfc.objects.order_by('number')
    context = {
        'rfc_list': rfc_list,
    }
    return render(request, 'directory/index_rfc.html', context)

def detail_cs(request, cs_name):
    cipher_suite = get_object_or_404(CipherSuite, pk=cs_name)
    referring_rfc_list = cipher_suite.rfcs.all()
    context = {
        'cipher_suite': cipher_suite,
        'referring_rfc_list': referring_rfc_list,
    }
    return render(request, 'directory/detail_cs.html', context)

def detail_rfc(request, rfc_number):
    rfc = get_object_or_404(Rfc, pk=rfc_number)
    defined_cipher_suites = rfc.cipher_suites.all()
    obsoleted_by = rfc.obsoleted_by
    obsoletes = rfc.obsoletes
    context = {
        'rfc': rfc,
        'defined_cipher_suites': defined_cipher_suites,
        'obsoleted_by': obsoleted_by,
        'obsoletes': obsoletes,
    }
    return render(request, 'directory/detail_rfc.html', context)

