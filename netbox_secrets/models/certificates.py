from django.conf import settings
from django.contrib.contenttypes.fields import GenericRelation
from django.db import models
from django.urls import reverse

from .base import BaseSecret
from .secrets import SecretRole

plugin_settings = settings.PLUGINS_CONFIG['netbox_secrets']


class Certificate(BaseSecret):
    class Meta:
        ordering = ('role', 'name', 'pk')
        constraints = [
            models.UniqueConstraint(
                name='%(app_label)s_%(class)s_object_role_name',
                fields=['assigned_object_type', 'assigned_object_id', 'role', 'name'],
                violation_error_message='Certificates must have a unique name within a given object and role.',
            )
        ]

    def __str__(self):
        return self.name or 'Certificate'

    def get_absolute_url(self):
        return reverse('plugins:netbox_secrets:certificate', args=[self.pk])

    @classmethod
    def get_prerequisite_models(cls):
        return [SecretRole]


if plugin_settings.get('enable_contacts', False):
    GenericRelation(
        to='tenancy.ContactAssignment',
        related_query_name='secret',
    ).contribute_to_class(Certificate, 'contacts')
