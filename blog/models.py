# django imports
from django.db import models
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.models import User
from django.db.models.signals import pre_save
from django.dispatch import receiver

# general python imports
import re


#####################
# Model definitions #
#####################


class Post(models.Model):
    class Meta:
        ordering=['-first_published']
        verbose_name=_('post')
        verbose_name_plural=_('posts')

    title = models.CharField(
        primary_key=True,
        max_length=100,
    )
    slug = models.SlugField(
        unique=True,
        editable=False,
    )
    author = models.ForeignKey(
        User,
        blank=True,
        null=True,
        on_delete=models.CASCADE,
    )
    intro = models.TextField(
        max_length = 500,
        blank=True,
    )
    text = models.TextField()
    category = models.ForeignKey(
        'Category',
        on_delete=models.CASCADE,
    )
    tags = models.ManyToManyField(
        'Tag',
        blank=True,
    )
    published = models.BooleanField(
        default=True,
    )
    first_published = models.DateField(
        auto_now_add=True,
    )
    last_edited = models.DateField(
        auto_now=True,
    )

    def get_year(self):
        return f"{self.first_published.year:4d}"

    def get_month(self):
        return f"{self.first_published.month:02d}"

    def get_day(self):
        return f"{self.first_published.day:02d}"

    def __str__(self):
        return self.title


class Category(models.Model):
    class Meta:
        ordering=['name']
        verbose_name=_('category')
        verbose_name_plural=_('categories')

    name = models.CharField(
        primary_key=True,
        max_length=50,
    )
    description = models.CharField(
        max_length=250,
        blank=True,
    )
    slug = models.SlugField(
        unique=True,
        editable=False,
    )

    def __str__(self):
        return self.name


class Tag(models.Model):
    class Meta:
        ordering=['name']
        verbose_name=_('tag')
        verbose_name_plural=_('tags')

    name = models.CharField(
        primary_key=True,
        max_length=50,
    )
    slug = models.SlugField(
        unique=True,
        editable=False,
    )

    def __str__(self):
        return self.name


######################
# Signal definitions #
######################

def slugify(text):
    """Replaces whitespace with dashes and removes other special symbols."""
    concatenated = re.sub('\s+', '-', text.lower())
    return re.sub('[^A-Za-z0-9_-]', '', concatenated)

@receiver(pre_save, sender=Post)
def create_slug_from_post_title(sender, instance, *args, **kwargs):
    """Automatically generates a slug from the post's title."""
    if not instance.slug:
        instance.slug = slugify(instance.title)

@receiver(pre_save, sender=Category)
def create_slug_from_category_name(sender, instance, *args, **kwargs):
    """Automatically generates a slug from the category's name."""
    if not instance.slug:
        instance.slug = slugify(instance.name)

@receiver(pre_save, sender=Tag)
def create_slug_from_tag_name(sender, instance, *args, **kwargs):
    """Automatically generates a slug from the tag's name."""
    if not instance.slug:
        instance.slug = slugify(instance.name)
