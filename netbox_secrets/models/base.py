from Crypto.Cipher import AES
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.contenttypes.fields import GenericForeignKey
from django.db import models

from netbox.models import NetBoxModel
from ..utils import *

__all__ = [
    'BaseSecret'
]

plugin_settings = settings.PLUGINS_CONFIG['netbox_secrets']


class BaseSecret(NetBoxModel):
    assigned_object_type = models.ForeignKey(
        to='contenttypes.ContentType',
        on_delete=models.PROTECT
    )

    assigned_object_id = models.PositiveIntegerField()

    assigned_object = GenericForeignKey(
        ct_field='assigned_object_type',
        fk_field='assigned_object_id'
    )

    role = models.ForeignKey(
        to='SecretRole',
        on_delete=models.PROTECT,
        related_name='%(class)s'
    )

    name = models.CharField(
        max_length=100,
        blank=True
    )

    ciphertext = models.BinaryField(
        max_length=65568,
        editable=False,  # 128-bit IV + 16-bit pad length + 65535B secret + 15B padding
    )

    hash = models.CharField(
        max_length=128,
        editable=False
    )

    plaintext = None
    csv_headers = ['assigned_object_type', 'assigned_object_id', 'role', 'name', 'plaintext']

    class Meta:
        abstract = True

    def __init__(self, *args, **kwargs):
        self.plaintext = kwargs.pop('plaintext', None)
        super().__init__(*args, **kwargs)

    def to_csv(self):
        return (
            f'{self.assigned_object_type.app_label}.{self.assigned_object_type.model}',
            self.assigned_object_id,
            self.role,
            self.name,
            self.plaintext or '',
        )

    def _pad(self, s):
        """
        Prepend the length of the plaintext (2B) and pad with garbage to a multiple of 16B (minimum of 64B).
        +--+--------+-------------------------------------------+
        |LL|MySecret|xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx|
        +--+--------+-------------------------------------------+
        """
        s = s.encode('utf8')
        if len(s) > 65535:
            raise ValueError("Maximum plaintext size is 65535 bytes.")

        # Minimum ciphertext size is 64 bytes to conceal the length of short secrets.
        if len(s) <= 62:
            pad_length = 62 - len(s)
        elif (len(s) + 2) % 16:
            pad_length = 16 - ((len(s) + 2) % 16)
        else:
            pad_length = 0

        header = bytes([len(s) >> 8]) + bytes([len(s) % 256])

        return header + s + os.urandom(pad_length)

    def _unpad(self, s):
        """
        Consume the first two bytes of s as a plaintext length indicator and return only that many bytes as the
        plaintext.
        """
        if isinstance(s[0], str):
            plaintext_length = (ord(s[0]) << 8) + ord(s[1])
        else:
            plaintext_length = (s[0] << 8) + s[1]
        return s[2: plaintext_length + 2].decode('utf8')

    def encrypt(self, secret_key):
        """
        Generate a random initialization vector (IV) for AES. Pad the plaintext to the AES block size (16 bytes) and
        encrypt. Prepend the IV for use in decryption. Finally, record the SHA256 hash of the plaintext for validation
        upon decryption.
        """
        if self.plaintext is None:
            raise Exception("Must unlock or set plaintext before locking.")

        # Pad and encrypt plaintext
        iv = os.urandom(16)
        aes = AES.new(secret_key, AES.MODE_CFB, iv)
        self.ciphertext = iv + aes.encrypt(self._pad(self.plaintext))

        # Generate SHA256 using Django's built-in password hashing mechanism
        self.hash = make_password(self.plaintext, hasher=SecretValidationHasher())

        self.plaintext = None

    def decrypt(self, secret_key):
        """
        Consume the first 16 bytes of self.ciphertext as the AES initialization vector (IV). The remainder is decrypted
        using the IV and the provided secret key. Padding is then removed to reveal the plaintext. Finally, validate the
        decrypted plaintext value against the stored hash.
        """
        if self.plaintext is not None:
            return
        if not self.ciphertext:
            raise Exception("Must define ciphertext before unlocking.")

        # Decrypt ciphertext and remove padding
        iv = bytes(self.ciphertext[0:16])
        ciphertext = bytes(self.ciphertext[16:])
        aes = AES.new(secret_key, AES.MODE_CFB, iv)
        plaintext = self._unpad(aes.decrypt(ciphertext))

        # Verify decrypted plaintext against hash
        if not self.validate(plaintext):
            raise ValueError("Invalid key or ciphertext!")

        self.plaintext = plaintext

    def validate(self, plaintext):
        """
        Validate that a given plaintext matches the stored hash.
        """
        if not self.hash:
            raise Exception("Hash has not been generated for this secret.")
        return check_password(plaintext, self.hash, preferred=SecretValidationHasher())

    @property
    def enable_contacts(self):
        return plugin_settings.get('enable_contacts', False)
