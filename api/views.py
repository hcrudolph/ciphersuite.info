from django.shortcuts import get_object_or_404, render, redirect
from django.http import JsonResponse, Http404
from directory.models import *
import json


def reformat_cs(cs):
    sec_lvl = get_security_by_csname(cs['name'])
    cs.update({"security_level": sec_lvl})
    return {cs.pop('name'):cs}


def reformat_rfc(rfc):
    return {rfc.pop('number'):rfc}


def api_root(request):
    return redirect('/static/openapi.json')


def cs_all(request):
    cs = [reformat_cs(x.to_dict()) for x in CipherSuite.objects.all()]
    return JsonResponse({"ciphersuites":cs}, safe=False)


def cs_single(request, iana_name):
    cs = get_object_or_404(CipherSuite, pk=iana_name)
    return JsonResponse(reformat_cs(cs.to_dict()), safe=False)


def get_security_by_csname(name):
    if CipherSuite.objects.get(pk=name).insecure:
        return 'insecure'
    elif CipherSuite.objects.get(pk=name).weak:
        return 'weak'
    elif CipherSuite.objects.get(pk=name).secure:
        return 'secure'
    elif CipherSuite.objects.get(pk=name).recommended:
        return 'recommended'


def cs_by_security(request, sec_level):
    if sec_level == 'insecure':
        cs = [reformat_cs(x.to_dict()) for x in CipherSuite.custom_filters.insecure()]
    elif sec_level == 'weak':
        cs = [reformat_cs(x.to_dict()) for x in CipherSuite.custom_filters.weak()]
    elif sec_level == 'secure':
        cs = [reformat_cs(x.to_dict()) for x in CipherSuite.custom_filters.secure()]
    elif sec_level == 'recommended':
        cs = [reformat_cs(x.to_dict()) for x in CipherSuite.custom_filters.recommended()]
    else:
        raise Http404(f"Security level '{sec_level}' does not exist.")

    return JsonResponse({"ciphersuites":cs}, safe=False)


def cs_by_software(request, software):
    if software == 'openssl':
        cs = [reformat_cs(x.to_dict()) for x in CipherSuite.objects.exclude(openssl_name="")]
    elif software == 'gnutls':
        cs = [reformat_cs(x.to_dict()) for x in CipherSuite.objects.exclude(gnutls_name="")]
    else:
        raise Http404(f"Software '{software}' does not exist.")
    
    return JsonResponse({"ciphersuites":cs}, safe=False)


def cs_by_tlsversion(request, tlsv):
    if tlsv == '10':
        cs = [reformat_cs(x.to_dict()) for x in CipherSuite.objects.filter(
                tls_version__short="10")]
    elif tlsv == '11':
        cs = [reformat_cs(x.to_dict()) for x in CipherSuite.objects.filter(
                tls_version__short="11")]
    elif tlsv == '12':
        cs = [reformat_cs(x.to_dict()) for x in CipherSuite.objects.filter(
                tls_version__short="12")]
    elif tlsv == '13':
        cs = [reformat_cs(x.to_dict()) for x in CipherSuite.objects.filter(
                tls_version__short="13")]
    else:
        raise Http404(f"TLS version '{tlsv}' does not exist.")
    
    return JsonResponse({"ciphersuites":cs}, safe=False)


def rfc_all(request):
    rfc = [reformat_rfc(x.to_dict()) for x in Rfc.objects.all()]
    return JsonResponse({"rfcs":rfc}, safe=False)


def rfc_single(request, rfc_number):
    rfc = get_object_or_404(Rfc, pk=rfc_number)
    return JsonResponse(reformat_rfc(rfc.to_dict()), safe=False)