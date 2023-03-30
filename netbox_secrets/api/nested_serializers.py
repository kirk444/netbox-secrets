from rest_framework import serializers

from netbox.api.serializers import WritableNestedSerializer
from netbox_secrets.models import Certificate, Secret, SecretRole

__all__ = [
    'NestedCertificateSerializer',
    'NestedSecretRoleSerializer',
    'NestedSecretSerializer',
]


class NestedSecretSerializer(WritableNestedSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_secrets-api:secret-detail')

    class Meta:
        model = Secret
        fields = ['id', 'url', 'display', 'name']


class NestedSecretRoleSerializer(WritableNestedSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_secrets-api:secretrole-detail')
    secret_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = SecretRole
        fields = ['id', 'url', 'display', 'name', 'slug', 'secret_count']


class NestedCertificateSerializer(WritableNestedSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_secrets-api:certificate-detail')

    class Meta:
        model = Certificate
        fields = ['id', 'url', 'display', 'name']
