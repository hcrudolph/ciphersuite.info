from django.http import HttpRequest, Http404, HttpResponse, HttpResponseRedirect
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.shortcuts import get_object_or_404, render
from django.contrib.auth.models import User
from directory.forms import NavbarSearchForm
from datetime import datetime

from .models import *

def recent_posts(request):
    posts = Post.objects.all().exclude(published=False)

    context = {
        'posts': posts,
        'navbar_context': 'blog',
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'blog/recent_posts.html', context)

def tag_post_archive(request, tag_slug):
    tag = Tag.objects.get(slug=tag_slug)

    try:
        post_list = Post.objects.filter(tags__slug=tag_slug)
    except Post.DoesNotExist:
        raise Http404("No Post matches the given query.")

    context = {
        'term': tag.name,
        'navbar_context': 'blog',
        'archive_type': 'by_tag',
        'post_list': post_list,
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'blog/post_archive.html', context)

def author_post_archive(request, author_slug):
    try:
        post_list = Post.objects.filter(author__username=author_slug)
    except Post.DoesNotExist:
        raise Http404("No Post matches the given query.")

    context = {
        'term': author_slug,
        'navbar_context': 'blog',
        'archive_type': 'by_author',
        'post_list': post_list,
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'blog/post_archive.html', context)

def category_post_archive(request, category_slug):
    category = Category.objects.get(slug=category_slug)
    try:
        post_list = Post.objects.filter(category__slug=category_slug)
    except Post.DoesNotExist:
        raise Http404("No Post matches the given query.")

    context = {
        'term': category.name,
        'navbar_context': 'blog',
        'archive_type': 'by_category',
        'post_list': post_list,
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'blog/post_archive.html', context)

def tag_archive(request):
    tags = Tag.objects.all()

    context = {
        'navbar_context': 'blog',
        'tag_list': tags,
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'blog/tag_archive.html', context)

def category_archive(request):
    categories = Category.objects.all()

    context = {
        'navbar_context': 'blog',
        'category_list': categories,
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'blog/category_archive.html', context)

def author_archive(request):
    usernames = set()
    for uid in Post.objects.all().values_list('author', flat=True):
        user = User.objects.get(pk=uid)
        usernames.add(user.username)

    context = {
        'navbar_context': 'blog',
        'author_list': usernames,
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'blog/author_archive.html', context)

def yearly_post_archive(request, year):
    post_list = Post.objects.filter(
        first_published__year=year,
    )

    context = {
        'term': f"{year}",
        'navbar_context': 'blog',
        'archive_type': 'by_year',
        'post_list': post_list,
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'blog/post_archive.html', context)

def monthly_post_archive(request, year, month):
    post_list = Post.objects.filter(
        first_published__year=year,
        first_published__month=month,
    )

    context = {
        'term': datetime.strptime(f"{year}/{month}", '%Y/%m'),
        'navbar_context': 'blog',
        'archive_type': 'by_month',
        'post_list': post_list,
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'blog/post_archive.html', context)

def daily_post_archive(request, year, month, day):
    post_list = Post.objects.filter(
        first_published__year=year,
        first_published__month=month,
        first_published__day=day,
    )

    context = {
        'term': datetime.strptime(f"{year}/{month}/{day}", '%Y/%m/%d'),
        'navbar_context': 'blog',
        'archive_type': 'by_day',
        'post_list': post_list,
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'blog/post_archive.html', context)

def single_post(request, year, month, day, post_slug):
    try:
        post = Post.objects.get(slug=post_slug)
    except Post.DoesNotExist:
        raise Http404("No Post matches the given query.")

    context = {
        'post': post,
        'navbar_context': 'blog',
        'search_form': NavbarSearchForm(),
    }

    return render(request, 'blog/single_post.html', context)
