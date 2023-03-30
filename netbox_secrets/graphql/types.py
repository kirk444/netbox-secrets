from netbox.graphql.types import NetBoxObjectType, ObjectType

from netbox_secrets import filtersets, models

__all__ = [
    'CertificateType',
    'SecretRoleType',
    'SecretType',
]


class CertificateType(NetBoxObjectType):
    class Meta:
        model = models.Certificate
        fields = '__all__'
        filterset_class = filtersets.CertificateFilterSet


class SecretRoleType(ObjectType):
    class Meta:
        model = models.SecretRole
        fields = '__all__'
        filterset_class = filtersets.SecretRoleFilterSet


class SecretType(NetBoxObjectType):
    class Meta:
        model = models.Secret
        fields = '__all__'
        filterset_class = filtersets.SecretFilterSet
