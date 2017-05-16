from django import forms

class MainSearchForm(forms.Form):
    search_term = forms.CharField(
        label="",
        max_length=100,
        widget=forms.TextInput(
            attrs={
                'class': 'form-control input-lg',
                'placeholder': 'cipher, algorithm, vulnerability...',
            }
        ),
    )


class NavbarSearchForm(forms.Form):
    search_term = forms.CharField(
        label="",
        max_length=100,
        widget=forms.TextInput(
            attrs={
                'class': 'form-control',
                'placeholder': 'Search...',
            }
        ),
    )


