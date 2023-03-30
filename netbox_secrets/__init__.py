from importlib.metadata import metadata

from extras.plugins import PluginConfig

metadata = metadata('netbox_secrets')


class NetBoxSecrets(PluginConfig):
    name = metadata.get('Name').replace('-', '_')
    verbose_name = metadata.get('Summary')
    description = metadata.get('Description')
    version = metadata.get('Version')
    author = metadata.get('Author')
    author_email = metadata.get('Author-email')
    base_url = 'secrets'
    min_version = '3.5.0'
    max_version = '3.5.99'
    required_settings = []
    default_settings = {
        'apps': ['dcim.device', 'virtualization.virtualmachine'],
        'display_default': 'left_page',
        'display_setting': {},
        'enable_contacts': False,
        'public_key_size': 2048,
    }

    def ready(self):
        # This is a hack to get around the error: `AppRegistryNotReady: Models aren't loaded yet.`
        from django.conf import settings
        from django.contrib.contenttypes.fields import GenericRelation
        from django.contrib.contenttypes.models import ContentType

        plugin_settings = settings.PLUGINS_CONFIG[self.name]

        for app in plugin_settings['apps']:
            app_label, model = app.split('.')
            klass = ContentType.objects.get(app_label=app_label, model=model).model_class()

            GenericRelation(
                to='netbox_secrets.Secret',
                content_type_field='assigned_object_type',
                object_id_field='assigned_object_id',
                related_query_name=model,
            ).contribute_to_class(klass, 'secrets')

            GenericRelation(
                to='netbox_secrets.Certificate',
                content_type_field='assigned_object_type',
                object_id_field='assigned_object_id',
                related_query_name=model,
            ).contribute_to_class(klass, 'secrets')


config = NetBoxSecrets
