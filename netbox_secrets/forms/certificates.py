from django import forms

from utilities.forms import (
    DynamicModelMultipleChoiceField,
    TagFilterField
)
from .base import *
from ..models import Certificate

__all__ = [
    'CertificateForm',
    'CertificateFilterForm',
]


#
# Certificates
#

class CertificateForm(BaseSecretForm):
    plaintext = forms.CharField()

    plaintext2 = forms.CharField()

    class Meta:
        model = Certificate
        fields = (
            'role',
            'name',
            'plaintext',
            'plaintext2',
            'tags',
        )


class CertificateFilterForm(BaseSecretFilterForm):
    model = Certificate
    name = DynamicModelMultipleChoiceField(queryset=Certificate.objects.all(), required=False)

    tag = TagFilterField(model)
