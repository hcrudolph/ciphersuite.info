from django.shortcuts import get_object_or_404, render, redirect
from django.http import JsonResponse, HttpResponse, Http404
from directory.models import CipherSuite, Rfc
import json


def reformat_cs(cs):
    # replace int security rating by string
    if cs['security'] == 0:
        cs['security'] = "recommended"
    elif cs['security'] == 1:
        cs['security'] = "secure"
    elif cs['security'] == 2:
        cs['security'] = "weak"
    elif cs['security'] == 3:
        cs['security'] = "insecure"

    return {cs.pop('name'):cs}


def reformat_rfc(rfc):
    return {rfc.pop('number'):rfc}


def api_root(request):
    api_definition = open('./static/openapi.json', 'rb')
    response = HttpResponse(content=api_definition)
    response['Content-Type'] = 'application/json'
    return response


def cs_all(request):
    cs = [reformat_cs(x.to_dict()) for x in CipherSuite.objects.all()]
    return JsonResponse({"ciphersuites":cs}, safe=False)


def cs_single(request, iana_name):
    cs = get_object_or_404(CipherSuite, pk=iana_name)
    return JsonResponse(reformat_cs(cs.to_dict()), safe=False)


def cs_by_security(request, sec_level):
    if sec_level == 'insecure':
        cs = [reformat_cs(cs.to_dict()) for cs in
                CipherSuite.objects.filter(security=3)]
    elif sec_level == 'weak':
        cs = [reformat_cs(cs.to_dict()) for cs in
                CipherSuite.objects.filter(security=2)]
    elif sec_level == 'secure':
        cs = [reformat_cs(cs.to_dict()) for cs in
                CipherSuite.objects.filter(security=1)]
    elif sec_level == 'recommended':
        cs = [reformat_cs(cs.to_dict()) for cs in
                CipherSuite.objects.filter(security=0)]
    else:
        raise Http404(f"Security level '{sec_level}' does not exist.")

    return JsonResponse({"ciphersuites":cs}, safe=False)


def cs_by_software(request, software):
    if software == 'openssl':
        cs = [reformat_cs(cs.to_dict()) for cs in
                CipherSuite.objects.exclude(openssl_name="")]
    elif software == 'gnutls':
        cs = [reformat_cs(cs.to_dict()) for cs in
                CipherSuite.objects.exclude(gnutls_name="")]
    else:
        raise Http404(f"Software '{software}' does not exist.")

    return JsonResponse({"ciphersuites":cs}, safe=False)


def cs_by_tlsversion(request, tlsv):
    if tlsv == '10':
        cs = [reformat_cs(cs.to_dict()) for cs in
                CipherSuite.objects.filter(tls_version__short="10")]
    elif tlsv == '11':
        cs = [reformat_cs(cs.to_dict()) for cs in
                CipherSuite.objects.filter(tls_version__short="11")]
    elif tlsv == '12':
        cs = [reformat_cs(cs.to_dict()) for cs in
                CipherSuite.objects.filter(tls_version__short="12")]
    elif tlsv == '13':
        cs = [reformat_cs(cs.to_dict()) for cs in
                CipherSuite.objects.filter(tls_version__short="13")]
    else:
        raise Http404(f"TLS version '{tlsv}' does not exist.")

    return JsonResponse({"ciphersuites":cs}, safe=False)


def rfc_all(request):
    rfc = [reformat_rfc(x.to_dict()) for x in Rfc.objects.all()]
    return JsonResponse({"rfcs":rfc}, safe=False)


def rfc_single(request, rfc_number):
    rfc = get_object_or_404(Rfc, pk=rfc_number)
    return JsonResponse(reformat_rfc(rfc.to_dict()), safe=False)