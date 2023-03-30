import logging

from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db.utils import OperationalError

from extras.plugins import PluginTemplateExtension
from .models import Certificate, Secret

logger = logging.getLogger(__name__)
plugin_settings = settings.PLUGINS_CONFIG.get('netbox_secrets')
template_extensions = []


def _secrets_panel(self, klass):
    obj = self.context['object']
    app_label, model = self.model.split('.')
    assigned_object_type = ContentType.objects.get(app_label=app_label, model=model).id

    return self.render(
        'netbox_secrets/inc/secrets_panel.html',
        extra_context={
            'secrets': klass.objects.filter(assigned_object_type=assigned_object_type, assigned_object_id=obj.id),
        },
    )


def secrets_panel(self):
    return _secrets_panel(self, Secret)


def certificates_panel(self):
    return _secrets_panel(self, Certificate)


def get_display_on(app_model):
    """Get preferred display location for app_model"""
    display_on = plugin_settings.get('display_default')

    if display_setting := plugin_settings.get('display_setting'):
        display_on = display_setting.get(app_model, display_on)

    return display_on


# Generate plugin extensions for the defined classes
try:
    for app_model in plugin_settings.get('apps'):
        app_label, model = app_model.split('.')
        klass_name = f'{app_label}_{model}_plugin_template_extension'
        dynamic_klass_certificates = type(
            klass_name,
            (PluginTemplateExtension,),
            {'model': app_model, get_display_on(app_model): certificates_panel},
        )
        dynamic_klass_secrets = type(
            klass_name,
            (PluginTemplateExtension,),
            {'model': app_model, get_display_on(app_model): secrets_panel},
        )
        template_extensions.append(dynamic_klass_certificates)
        template_extensions.append(dynamic_klass_secrets)
except OperationalError as e:
    # This happens when the database is not yet ready
    logger.warning(f'Database not ready, skipping plugin extensions: {e}')
except Exception as e:
    # Unexpected error
    raise Exception(f'Unexpected error: {e}')
