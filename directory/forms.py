from django import forms

class MainSearchForm(forms.Form):
    q = forms.CharField(
        label="",
        max_length=100,
        widget=forms.TextInput(
            attrs={
                'class': 'form-control form-control-lg',
                'placeholder': 'cipher, algorithm, rfc, vulnerability...',
            }
        ),
    )

class NavbarSearchForm(forms.Form):
    q = forms.CharField(
        label="",
        max_length=100,
        widget=forms.TextInput(
            attrs={
                'class': 'form-control',
                'placeholder': 'Search',
            }
        ),
    )
