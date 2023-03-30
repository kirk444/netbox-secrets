from Crypto.Util import strxor
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import User
from django.contrib.contenttypes.fields import GenericRelation
from django.core.exceptions import ValidationError
from django.db import models
from django.urls import reverse
from django.utils.encoding import force_bytes

from netbox.models import NetBoxModel
from netbox.models.features import ChangeLoggingMixin, WebhooksMixin
from utilities.querysets import RestrictedQuerySet
from .base import BaseSecret
from ..exceptions import InvalidKey
from ..querysets import UserKeyQuerySet
from ..utils import *

__all__ = [
    'Secret',
    'SecretRole',
    'SessionKey',
    'UserKey',
]

plugin_settings = settings.PLUGINS_CONFIG.get('netbox_secrets', {})


class UserKey(ChangeLoggingMixin, WebhooksMixin):
    """
    A UserKey stores a user's personal RSA (public) encryption key, which is used to generate their unique encrypted
    copy of the master encryption key. The encrypted instance of the master key can be decrypted only with the user's
    matching (private) decryption key.
    """

    id = models.BigAutoField(primary_key=True)
    user = models.OneToOneField(to=User, on_delete=models.CASCADE, related_name='user_key', editable=False)
    public_key = models.TextField(
        verbose_name='RSA public key',
    )
    master_key_cipher = models.BinaryField(max_length=512, blank=True, null=True, editable=False)

    objects = UserKeyQuerySet.as_manager()

    class Meta:
        ordering = ['user__username']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Store the initial public_key and master_key_cipher to check for changes on save().
        self.__initial_public_key = self.public_key
        self.__initial_master_key_cipher = self.master_key_cipher

    def __str__(self):
        return self.user.username

    def clean(self):
        super().clean()

        if self.public_key:

            if isinstance(self.public_key, bytes):
                self.public_key = self.public_key.decode('utf-8')

            # Validate the public key format
            if self.public_key.startswith('ssh-rsa '):
                raise ValidationError(
                    {
                        'public_key': "OpenSSH line format is not supported. Please ensure that your public is in PEM (base64) format.",
                    },
                )

            try:
                pubkey = RSA.importKey(self.public_key)
            except ValueError as e:
                raise ValidationError(
                    {
                        'public_key': f"Invalid RSA key: {e}",
                    },
                )
            if pubkey.has_private():
                raise ValidationError(
                    {'public_key': "This looks like a private key. Please provide your public RSA key."},
                )
            try:
                PKCS1_OAEP.new(pubkey)
            except Exception:
                raise ValidationError(
                    {'public_key': "Error validating RSA key. Please ensure that your key supports PKCS#1 OAEP."},
                )

            # Validate the public key length
            pubkey_length = pubkey.size_in_bits()
            if pubkey_length < settings.PLUGINS_CONFIG['netbox_secrets']['public_key_size']:
                raise ValidationError(
                    {
                        'public_key': "Insufficient key length. Keys must be at least {} bits long.".format(
                            settings.PLUGINS_CONFIG['netbox_secrets']['public_key_size'],
                        ),
                    },
                )
            # We can't use keys bigger than our master_key_cipher field can hold
            if pubkey_length > 4096:
                raise ValidationError(
                    {
                        'public_key': "Public key size ({}) is too large. Maximum key size is 4096 bits.".format(
                            pubkey_length,
                        ),
                    },
                )

    def save(self, *args, **kwargs):

        # Check whether public_key has been modified. If so, nullify the initial master_key_cipher.
        if self.__initial_master_key_cipher and self.public_key != self.__initial_public_key:
            self.master_key_cipher = None

        # If no other active UserKeys exist, generate a new master key and use it to activate this UserKey.
        if self.is_filled() and not self.is_active() and not UserKey.objects.active().count():
            master_key = generate_random_key()
            self.master_key_cipher = encrypt_master_key(master_key, self.public_key)

        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):

        # If Secrets exist and this is the last active UserKey, prevent its deletion. Deleting the last UserKey will
        # result in the master key being destroyed and rendering all Secrets inaccessible.
        if Secret.objects.count() and [uk.pk for uk in UserKey.objects.active()] == [self.pk]:
            raise Exception(
                "Cannot delete the last active UserKey when Secrets exist! This would render all secrets "
                "inaccessible.",
            )

        super().delete(*args, **kwargs)

    def is_filled(self):
        """
        Returns True if the UserKey has been filled with a public RSA key.
        """
        return bool(self.public_key)

    is_filled.boolean = True

    def is_active(self):
        """
        Returns True if the UserKey has been populated with an encrypted copy of the master key.
        """
        return self.master_key_cipher is not None

    is_active.boolean = True

    def get_master_key(self, private_key):
        """
        Given the User's private key, return the encrypted master key.
        """
        if not self.is_active:
            raise ValueError("Unable to retrieve master key: UserKey is inactive.")
        try:
            return decrypt_master_key(force_bytes(self.master_key_cipher), private_key)
        except ValueError:
            return None

    def activate(self, master_key):
        """
        Activate the UserKey by saving an encrypted copy of the master key to the database.
        """
        if not self.public_key:
            raise Exception("Cannot activate UserKey: Its public key must be filled first.")
        self.master_key_cipher = encrypt_master_key(master_key, self.public_key)
        self.save()


class SessionKey(models.Model):
    """
    A SessionKey stores a User's temporary key to be used for the encryption and decryption of secrets.
    """

    id = models.BigAutoField(primary_key=True)
    userkey = models.OneToOneField(to='UserKey', on_delete=models.CASCADE, related_name='session_key', editable=False)
    cipher = models.BinaryField(max_length=512, editable=False)
    hash = models.CharField(max_length=128, editable=False)
    created = models.DateTimeField(auto_now_add=True)

    key = None

    objects = RestrictedQuerySet.as_manager()

    class Meta:
        ordering = ['userkey__user__username']

    def __str__(self):
        return f'{self.userkey.user.username} (RSA)'

    def save(self, master_key=None, *args, **kwargs):

        if master_key is None:
            raise Exception("The master key must be provided to save a session key.")

        # Generate a random 256-bit session key if one is not already defined
        if self.key is None:
            self.key = generate_random_key()

        # Generate SHA256 hash using Django's built-in password hashing mechanism
        self.hash = make_password(self.key)

        # Encrypt master key using the session key
        self.cipher = strxor.strxor(self.key, master_key)

        super().save(*args, **kwargs)

    def get_master_key(self, session_key):

        # Validate the provided session key
        if not check_password(session_key, self.hash):
            raise InvalidKey("Invalid session key")

        # Decrypt master key using provided session key
        master_key = strxor.strxor(session_key, bytes(self.cipher))

        return master_key

    def get_session_key(self, master_key):

        # Recover session key using the master key
        session_key = strxor.strxor(master_key, bytes(self.cipher))

        # Validate the recovered session key
        if not check_password(session_key, self.hash):
            raise InvalidKey("Invalid master key")

        return session_key


class SecretRole(NetBoxModel):
    """
    A SecretRole represents an arbitrary functional classification of Secrets. For example, a user might define roles
    such as "Login Credentials" or "SNMP Communities."
    """

    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True)
    description = models.CharField(
        max_length=200,
        blank=True,
    )

    csv_headers = ['name', 'slug', 'description']

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('plugins:netbox_secrets:secretrole', args=[self.pk])

    def to_csv(self):
        return (
            self.name,
            self.slug,
            self.description,
        )


class Secret(BaseSecret):
    """
    A Secret stores an AES256-encrypted copy of sensitive data, such as passwords or secret keys. An irreversible
    SHA-256 hash is stored along with the ciphertext for validation upon decryption. Each Secret is assigned to exactly
    one NetBox object, and objects may have multiple Secrets associated with them. A name can optionally be defined
    along with the ciphertext; this string is stored as plain text in the database.

    A Secret can be up to 65,535 bytes (64KB - 1B) in length. Each secret string will be padded with random data to
    a minimum of 64 bytes during encryption in order to protect short strings from ciphertext analysis.
    """

    class Meta:
        ordering = ('role', 'name', 'pk')
        constraints = [
            models.UniqueConstraint(
                name='%(app_label)s_%(class)s_object_role_name',
                fields=['assigned_object_type', 'assigned_object_id', 'role', 'name'],
                violation_error_message='Secrets must have a unique name within a given object and role.',
            )
        ]

    def __str__(self):
        return self.name or 'Secret'

    def get_absolute_url(self):
        return reverse('plugins:netbox_secrets:secret', args=[self.pk])

    @classmethod
    def get_prerequisite_models(cls):
        return [SecretRole]


if plugin_settings.get('enable_contacts', False):
    GenericRelation(
        to='tenancy.ContactAssignment',
        related_query_name='secret',
    ).contribute_to_class(Secret, 'contacts')
