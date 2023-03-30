from django.urls import include, path

from utilities.urls import get_model_urls
from . import views

app_name = 'netbox_secrets'

urlpatterns = [
    # Secret roles
    path('secret-roles/', views.SecretRoleListView.as_view(), name='secretrole_list'),
    path('secret-roles/add/', views.SecretRoleEditView.as_view(), name='secretrole_add'),
    path('secret-roles/import/', views.SecretRoleBulkImportView.as_view(), name='secretrole_import'),
    path('secret-roles/edit/', views.SecretRoleBulkEditView.as_view(), name='secretrole_bulk_edit'),
    path('secret-roles/delete/', views.SecretRoleBulkDeleteView.as_view(), name='secretrole_bulk_delete'),
    path('secret-roles/<int:pk>/', include(get_model_urls(app_name, 'secretrole'))),
    # Secrets
    path('secrets/', views.SecretListView.as_view(), name='secret_list'),
    path('secrets/add/', views.SecretEditView.as_view(), name='secret_add'),
    path('secrets/delete/', views.SecretBulkDeleteView.as_view(), name='secret_bulk_delete'),
    path('secrets/<int:pk>/', include(get_model_urls(app_name, 'secret'))),
    # Certificates
    path('certificates/', views.CertificateListView.as_view(), name='certificate_list'),
    path('certificates/add/', views.CertificateEditView.as_view(), name='certificate_add'),
    path('certificates/delete/', views.CertificateBulkDeleteView.as_view(), name='certificate_bulk_delete'),
    path('certificates/<int:pk>/', include(get_model_urls(app_name, 'certificate'))),
    # User
    path('user-key/', views.UserKeyView.as_view(), name='userkey'),
    path('user-key/edit/', views.UserKeyEditView.as_view(), name='userkey_edit'),
    path('session-key/delete/', views.SessionKeyDeleteView.as_view(), name='sessionkey_delete'),
]
