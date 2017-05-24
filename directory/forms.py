from django import forms

class MainGetSearchForm(forms.Form):
    q = forms.CharField(
        label="",
        max_length=100,
        widget=forms.TextInput(
            attrs={
                'class': 'form-control input-lg',
                'placeholder': 'cipher, algorithm, vulnerability...',
            }
        ),
    )

class NavbarGetSearchForm(forms.Form):
    q = forms.CharField(
        label="",
        max_length=100,
        widget=forms.TextInput(
            attrs={
                'class': 'form-control',
                'placeholder': 'Search...',
            }
        ),
    )
