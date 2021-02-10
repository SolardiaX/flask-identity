# -*- coding: utf-8 -*-

"""
    identity._token_context
    ~~~~~~~~~~~~~~~~~~~
    Token Context of Flask-Identity

    :author: solardiax <solardiax@hotmail.com>
    :copyright: (c) 2020 by DreamEx Works.
    :license: GPL-3.0, see LICENSE for more details.
"""

import base64
import json
from datetime import timedelta
from cryptography.fernet import Fernet


class TokenContext(object):
    """
    | Class to generate/verify timestamped, signed and encrypted tokens.
    | Tokens can be used as cookie or request content.
    """

    def __init__(self, app) -> None:
        # Use the applications's SECRET_KEY as default.
        secret_key = app.config.get('SECRET_KEY', None)
        secret_key = app.config.get('IDENTITY_TOKEN_SALT', secret_key)

        if not secret_key:
            raise SystemError('Config setting SECRET_KEY or IDENTITY_TOKEN_SALT is missing.')

        # Print a warning if SECRET_KEY is too short
        key = secret_key.encode()
        if len(key) < 32:
            print('WARNING: Identity token secret key is shorter than 32 bytes.')
            key = key + b' ' * 32  # Make sure the key is at least 32 bytes long

        key32 = key[:32]
        base64_key32 = base64.urlsafe_b64encode(key32)

        # Create a Fernet cypher to encrypt data -- basically AES128 in CBC mode,
        # Encrypt, timestamp, sign, and base64-encode
        self.fernet = Fernet(base64_key32)

    def generate_token(self, *args, **kwargs) -> str:
        """
        Convert a list of args into an encrypted, timestamped, and signed token.
        :return: str An encrypted, timestamped, and signed token
        """
        data = {}
        for idx, arg in enumerate(args):
            if isinstance(arg, dict):
                data.update(**arg)
            else:
                data.update({str(idx): arg})

        if kwargs is not None:
            data.update(**kwargs)

        source = json.dumps(data)
        # Convert string to bytes
        source_bytes = source.encode()

        # Encrypt, timestamp, sign, and base64-encode
        encrypted_bytes = self.fernet.encrypt(source_bytes)

        # Convert bytes to string
        encrypted_str = encrypted_bytes.decode('utf-8')

        # Remove '=' padding if needed
        token = encrypted_str.strip('=')
        return token

    # noinspection PyBroadException
    def verify_token(self, token: str, ttl: timedelta = None) -> dict or None:
        """
        Verify signature, verify timestamp, and decrypt a token using ``cryptography.fernet.Fernet()``.
        :return Dictionary of origin token values.
                The keys is the index of arguments when use `*arg` with ``generate_token``,
                or is argument name when use `**kwargs` with ``generate_token``.
        """
        try:
            # Add '=' padding if needed
            if len(token) % 4:
                token += '=' * (4 - len(token) % 4)

            # Convert string to bytes
            encrypted_bytes = token.encode()

            # Verify signature, verify expiration, and decrypt using ``cryptography.fernet.Fernet()``
            source_bytes = self.fernet.decrypt(encrypted_bytes, ttl.total_seconds() if ttl else None)
            source = source_bytes.decode('utf-8')
            return json.loads(source)
        except Exception:
            return None
