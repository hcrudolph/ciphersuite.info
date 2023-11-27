from django.shortcuts import get_object_or_404, get_list_or_404
from django.http import JsonResponse, HttpResponse, Http404, HttpResponseBadRequest
from django.forms.models import model_to_dict
from django.conf import settings
from directory.models import *
from os.path import join

# Helper variables

secmap = dict(insecure=3, weak=2, secure=1, recommended=0)
vulnmap = dict(low=0, medium=1, high=2)

# Helper functions

def reformat_cs(cs):
    # replace int security rating by string
    if cs['security'] == 0:
        cs.update(security="recommended")
    elif cs['security'] == 1:
        cs.update(security="secure")
    elif cs['security'] == 2:
        cs.update(security="weak")
    elif cs['security'] == 3:
        cs.update(security="insecure")
    return {cs.pop('name'):cs}

def reformat_cs_v2(cs):
    # replace int security rating by string
    if cs['security'] == 0:
        cs.update(security="recommended")
    elif cs['security'] == 1:
        cs.update(security="secure")
    elif cs['security'] == 2:
        cs.update(security="weak")
    elif cs['security'] == 3:
        cs.update(security="insecure")
    cs.update(iana_name=cs.pop('name'))
    cs.pop('protocol_version')
    return cs

def reformat_rfc(rfc):
    return {rfc.pop('number'):rfc}

def reformat_vuln_v2(vuln):
    if vuln['severity'] == 0:
        vuln.update(severity="low")
    elif vuln['severity'] == 1:
        vuln.update(severity="medium")
    else:
        vuln.update(severity="high")
    return vuln

# Root

def api_root(request):
    api_definition = open(join(settings.BASE_DIR, 'static/openapi.json'), 'rb')
    response = HttpResponse(content=api_definition)
    response['Content-Type'] = 'application/json'
    return response

def api_root_v2(request):
    api_definition = open(join(settings.BASE_DIR, 'static/openapi_v2.json'), 'rb')
    response = HttpResponse(content=api_definition)
    response['Content-Type'] = 'application/json'
    return response

# Cyphersuites

def cs_all(request):
    cs = [reformat_cs(x.to_dict()) for x in CipherSuite.objects.all()]
    return JsonResponse({"ciphersuites":cs}, safe=False)

def cs_all_v2(request):
    cs = [reformat_cs_v2(x.to_dict()) for x in CipherSuite.objects.all()]
    return JsonResponse(cs, safe=False)

def cs_single(request, iana_name):
    cs = get_object_or_404(CipherSuite, pk=iana_name)
    return JsonResponse(reformat_cs(cs.to_dict()), safe=False)

def cs_single_v2(request, iana_name):
    cs = get_object_or_404(CipherSuite, pk=iana_name)
    return JsonResponse(reformat_cs_v2(cs.to_dict()), safe=False)

def cs_by_security(request, sec_level):
    cs = [reformat_cs(cs.to_dict()) for cs in
        get_list_or_404(CipherSuite, security=secmap[sec_level])]
    return JsonResponse({"ciphersuites":cs}, safe=False)

def cs_by_security_v2(request, sec_level):
    if not sec_level in secmap:
        return HttpResponseBadRequest('Illegal security rating.', status=400)

    cs = [reformat_cs_v2(cs.to_dict()) for cs in
        get_list_or_404(CipherSuite, security=secmap[sec_level])]
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

def cs_by_software_v2(request, software):
    if software == 'openssl':
        cs = [reformat_cs_v2(cs.to_dict()) for cs in
                CipherSuite.objects.exclude(openssl_name="")]
    elif software == 'gnutls':
        cs = [reformat_cs_v2(cs.to_dict()) for cs in
                CipherSuite.objects.exclude(gnutls_name="")]
    else:
        return HttpResponseBadRequest('Illegal software library.', status=400)

    return JsonResponse(cs, safe=False)

def cs_by_tlsversion(request, tlsv):
    cs = [reformat_cs(cs.to_dict()) for cs in
        get_list_or_404(CipherSuite, tls_version__short=tlsv)]
    return JsonResponse({"ciphersuites":cs}, safe=False)

def cs_by_tlsversion_v2(request, tls_version):
    if not tls_version in [10, 11, 12, 13]:
        return HttpResponseBadRequest('Illegal TLS version.', status=400)

    cs = [reformat_cs_v2(cs.to_dict()) for cs in
        get_list_or_404(CipherSuite, tls_version__short=tls_version)]
    return JsonResponse(cs, safe=False)

def search_cs_by_algorithm_v2(request, algo_type, search_term):
    if algo_type == "keyx":
        cs = [reformat_cs_v2(x.to_dict()) for x in
            get_list_or_404(CipherSuite,
            kex_algorithm__short_name__icontains=search_term)]
    elif algo_type == "auth":
        cs = [reformat_cs_v2(x.to_dict()) for x in
            get_list_or_404(CipherSuite,
            auth_algorithm__short_name__icontains=search_term)]
    elif algo_type == "encr":
        cs = [reformat_cs_v2(x.to_dict()) for x in
            get_list_or_404(CipherSuite,
            enc_algorithm__short_name__icontains=search_term)]
    elif algo_type == "hash":
        cs = [reformat_cs_v2(x.to_dict()) for x in
            get_list_or_404(CipherSuite,
            hash_algorithm__short_name__icontains=search_term)]
    else:
        return HttpResponseBadRequest('Illegal algorithm type.', status=400)
    return JsonResponse(cs, safe=False)

# RFCs

def rfc_all(request):
    rfc = [reformat_rfc(x.to_dict()) for x in Rfc.objects.all()]
    return JsonResponse({"rfcs":rfc}, safe=False)

def rfc_all_v2(request):
    rfc = [x.to_dict() for x in Rfc.objects.all()]
    return JsonResponse(rfc, safe=False)

def rfc_single(request, rfc_number):
    rfc = get_object_or_404(Rfc, pk=rfc_number)
    return JsonResponse(reformat_rfc(rfc.to_dict()), safe=False)

def rfc_single_v2(request, rfc_number):
    rfc = get_object_or_404(Rfc, pk=rfc_number)
    return JsonResponse(rfc.to_dict(), safe=False)

# Algorithms

def algo_all_v2(request):
    keyx = [dict(x.to_dict(), algo_type="keyx") for
            x in KexAlgorithm.objects.all()]
    auth = [dict(x.to_dict(), algo_type="auth") for
            x in AuthAlgorithm.objects.all()]
    encr = [dict(x.to_dict(), algo_type="encr") for
            x in EncAlgorithm.objects.all()]
    hash = [dict(x.to_dict(), algo_type="hash") for
            x in HashAlgorithm.objects.all()]
    algo = keyx + auth + encr + hash
    return JsonResponse(algo, safe=False)

def algo_by_type_v2(request, algo_type):
    if algo_type == "keyx":
        algo = [x.to_dict() for x in KexAlgorithm.objects.all()]
    elif algo_type == "auth":
        algo = [x.to_dict() for x in AuthAlgorithm.objects.all()]
    elif algo_type == "encr":
        algo = [x.to_dict() for x in EncAlgorithm.objects.all()]
    elif algo_type == "hash":
        algo = [x.to_dict() for x in HashAlgorithm.objects.all()]
    else:
        return HttpResponseBadRequest('Illegal algorithm type.', status=400)
    return JsonResponse(algo, safe=False)

def algo_by_severity_v2(request, severity):
    if not severity in vulnmap:
        return HttpResponseBadRequest('Illegal severity rating.', status=400)

    keyx = [dict(x.to_dict(), type="keyx") for x in
        get_list_or_404(KexAlgorithm, vulnerabilities__severity=vulnmap[severity])]
    auth = [dict(x.to_dict(), type="auth") for x in
        get_list_or_404(AuthAlgorithm, vulnerabilities__severity=vulnmap[severity])]
    encr = [dict(x.to_dict(), type="encr") for x in
        get_list_or_404(EncAlgorithm, vulnerabilities__severity=vulnmap[severity])]
    hash = [dict(x.to_dict(), type="hash") for x in
        get_list_or_404(HashAlgorithm, vulnerabilities__severity=vulnmap[severity])]
    algo = keyx + auth + encr + hash
    return JsonResponse(algo, safe=False)

# Vulnerabilities

def vuln_all_v2(request):
    vuln = [reformat_vuln_v2(x.to_dict()) for x in Vulnerability.objects.all()]
    return JsonResponse(vuln, safe=False)

def vuln_by_name_v2(request, vuln_name):
    vuln = get_object_or_404(Vulnerability, pk=vuln_name)
    return JsonResponse(reformat_vuln_v2(vuln.to_dict()), safe=False)

def vuln_by_severity_v2(request, severity):
    if not severity in vulnmap:
        return HttpResponseBadRequest('Illegal severity rating.', status=400)

    vuln = [reformat_vuln_v2(x.to_dict()) for x in
        get_list_or_404(Vulnerability, severity=vulnmap[severity])]
    return JsonResponse(vuln, safe=False)

def vuln_by_csname_v2(request, iana_name):
    cs = get_object_or_404(CipherSuite, pk=iana_name)
    vuln = cs.kex_algorithm.vulnerabilities.all() | \
        cs.auth_algorithm.vulnerabilities.all() | \
        cs.enc_algorithm.vulnerabilities.all() | \
        cs.hash_algorithm.vulnerabilities.all()
    result = [reformat_vuln_v2(x.to_dict()) for x in vuln]
    return JsonResponse(result, safe=False)
