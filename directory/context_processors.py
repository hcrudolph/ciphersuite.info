from directory.models import StaticPage

def static_pages(request):
    all_static_pages = StaticPage.objects.all()

    return {
        'static_pages': all_static_pages,
    }
