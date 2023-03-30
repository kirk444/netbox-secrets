from django import forms
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext as _

from netbox.forms import (
    NetBoxModelFilterSetForm,
    NetBoxModelForm,
)
from utilities.forms import (
    ContentTypeMultipleChoiceField,
    DynamicModelChoiceField,
    DynamicModelMultipleChoiceField,
)
from ..constants import SECRET_ASSIGNABLE_MODELS
from ..models import SecretRole

__all__ = [
    'BaseSecretForm',
    'BaseSecretFilterForm',
]


class BaseSecretForm(NetBoxModelForm):
    role = DynamicModelChoiceField(queryset=SecretRole.objects.all())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # A plaintext value is required when creating a new Secret
        if not self.instance.pk:
            self.fields['plaintext'].required = True

    def clean(self):
        super().clean()

        # Verify that the provided plaintext values match
        if self.cleaned_data['plaintext'] != self.cleaned_data['plaintext2']:
            raise forms.ValidationError(
                {'plaintext2': _("The two given plaintext values do not match. Please check your input.")},
            )


class BaseSecretFilterForm(NetBoxModelFilterSetForm):
    q = forms.CharField(required=False, label=_('Search'))
    assigned_object_type_id = ContentTypeMultipleChoiceField(
        queryset=ContentType.objects.filter(SECRET_ASSIGNABLE_MODELS),
        required=False,
        label=_('Object type(s)')
    )
    role_id = DynamicModelMultipleChoiceField(queryset=SecretRole.objects.all(), required=False, label=_('Role'))
