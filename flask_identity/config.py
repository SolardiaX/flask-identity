# -*- coding: utf-8 -*-

"""
    identity.config
    ~~~~~~~~~~~~~~~~~~~
    Default configuration of Flask-Identity

    :author: solardiax <solardiax@hotmail.com>
    :copyright: (c) 2020 by DreamEx Works.
    :license: GPL-3.0, see LICENSE for more details.
"""

from datetime import timedelta

default_config = {
    #: Specifies the view to redirect to if a user attempts to access a URL/endpoint that they do
    #: not have permission to access. If this value is ``None``, the user is presented with a default
    #: HTTP 403 response.
    #: Default: ``None``.
    'UNAUTHORIZED_VIEW': None,

    #: Specifies the default view to redirect to after a user logs in. This value can be set to a URL
    #: or an endpoint name.
    #: Default: ``'/'``.
    'POST_LOGIN_VIEW': '/',

    #: Specifies the default view to redirect to after a user logs out. This value can be set to a URL
    #: or an endpoint name.
    #: Default: ``'/'``.
    'POST_LOGOUT_VIEW': '/',

    #: A set of HTTP methods which are exempt from `login_required`.
    #: Default: ``'OPTIONS'``.
    'EXEMPT_METHODS': ['OPTIONS'],

    #: The identity field used to lookup user from ``DataStore``.
    #: The field must defined in ``UserMixin`` based user class.
    #: Default: ``'username'``.
    'IDENTITY_FIELD': 'username',
    #: The field used to store user token in session or request.
    #: Default: ``'token'``.
    'TOKEN_FIELD': 'token',
    #: The form field used to mark whether enable "remember me".
    #: Default: ``'remember'``
    'REMEBER_FIELD': 'remember',
    #: The form field used to store the url parameter when redirecting to the login view.
    #: Default: ``'next'``
    'NEXT_FIELD': 'next',

    #: Specifies the default "remember me" value used when logging in a user.
    #: Default: ``False``.
    'DEFAULT_REMEMBER_ME': False,

    #: The name of the "remember me" cookie.
    #: Default: ``'remember_me'``.
    'COOKIE_NAME': 'remember_me',
    #: The default time before the "remember me" cookie expires.
    #: Default: ``365 days``.
    'COOKIE_DURATION': timedelta(days=365),
    #: Whether the "remember me" cookie requires "Secure" attribute.
    #: Default: ``None``.
    'COOKIE_SECURE': None,
    #: The default domain name of the "remember me" cookie.
    #: Default: ``None``.
    'COOKIE_DOMAIN': None,
    #: The default path of the "remember me" cookie.
    #: Default: ``'/'``.
    'COOKIE_PATH': "/",
    #: Whether the "remember me" cookie uses HttpOnly or not.
    #: Default: ``False``.
    'COOKIE_HTTPONLY': False,
    #: Whether the "remember me" cookie will be refreshed by each request.
    #: #: Default: ``False``.
    'COOKIE_REFRESH_EACH_REQUEST': False,

    #: The id used to identity user in session or cookie.
    #: Default: ``'user_id'``.
    'SESSION_USER_ID_KEY': 'user_id',
    #: The mode to use session protection in.
    #: This can be either ``'basic'`` (the default) or ``'strong'``, or ``None`` to disable it.
    #: Default: ``'basic'``.
    'SESSION_PROTECTION': 'basic',
    #: The key to store "remember" stats in session.
    #: Default: ``'remember'``.
    'SESSION_REMEBER_KEY': 'remember',
    #: The key to store "remember_seconds" stats in session.
    #: Default: ``'remember_seconds'``.
    'SESSION_REMEBER_SECONDS_KEY': 'remember_seconds',
    #: The key to store "fresh" stats in session.
    #: Default: ``'_fresh'``.
    'SESSION_FRESH_KEY': '_fresh',
    #: The key to store session identity in session.
    #: Default: ``'_sid'``.
    'SESSION_ID_KEY': '_sid',

    #: The page the user is attempting to access is stored in the session
    #: or a url parameter when redirecting to the login view; This can be either
    #: ``'session'`` (the default) or ``'request'``.
    #: Default: ``'request'``.
    'NEXT_STORE': 'request',
    #: The key to store the source url when redirecting to the login view.
    #: The key will be used as url parameter in request or key in session.
    #: Default: ``'_next'``.
    'NEXT_KEY': '_next',

    #: The salt used to encrypt request or cookie token.
    #: If this value is ``None`` (the default), then will use ``SECRET_KEY`` as salt
    #: to encrypt token.
    #: Default: ``None``.
    'TOKEN_SALT': None,
    #: The key to pass the token in HTTP request header.
    #: Default: ``'X-IdentityManager-Auth'``
    'TOKEN_AUTHENTICATION_HEADER': 'X-IdentityManager-Auth',
    #: The parameter key to pass the token in HTTP request url.
    #: Default: ``'iauth'``.
    'TOKEN_AUTHENTICATION_ARG': 'iauth',

    #: Specifies the name for the Flask-Identity blueprint.
    #: Default: ``'identity'``.
    'BLUEPRINT_NAME': 'identity',
    'BLUEPRINT_URL_PREFIX': '/identity',
    'BLUEPRINT_SUBDOMAIN': None,
    'BLUEPRINT_TEMPLATE_FOLDER': 'templates',
    'BLUEPRINT_LOGIN_URL': "/login",
    'BLUEPRINT_LOGIN_METHODS': ['GET', 'POST'],
    'BLUEPRINT_LOGOUT_URL': "/logout",
    'BLUEPRINT_LOGOUT_METHODS': ['GET', 'POST'],
    'BLUEPRINT_LOGIN_USER_TEMPLATE': None,

    #: List of accepted password hashes.
    #: See `Passlib CryptContext docs on Constructor Keyword ``'schemes'``
    #: Example: ``['bcrypt', 'argon2']``
    #:      Creates new hashes with 'bcrypt' and verifies existing hashes with 'bcrypt' and 'argon2'.
    'HASH_SCHEMES': [
        "bcrypt",
        "argon2",
        "des_crypt",
        "pbkdf2_sha256",
        "pbkdf2_sha512",
        "sha256_crypt",
        "sha512_crypt",
        # And always last one...
        "plaintext",
    ],
    #: Dictionary of CryptContext keywords and hash options.
    #: See `Passlib CryptContext docs on Constructor Keywords`
    #: and `Passlib CryptContext docs on Algorithm Options`
    #: Example: ``dict(bcrypt__rounds=12, argon2__time_cost=2, argon2__memory_cost=512)``.
    #: Default: ``dict()``
    'HASH_OPTIONS': dict(),

    #: The custom identity data store to use. This can be either ``'pony' | 'sqlalchemy'``,
    #: or a custom class implement from ``IdentityStore`` and ``Store``.
    #: Default: ``None``
    'DATASTORE_ADAPTER': 'None',

    #: The user object can be activeable or not.
    #: This can be either a property name of ``User`` object,
    #: or ``None`` to disable it.
    #: Default: ``active``
    'ACTIVEABLE': None,

    #: The i8n message of ``UNAUTHENTICATED``.
    #: Default: ``'UNAUTHENTICATED'``.
    'MSG_UNAUTHENTICATED': 'UNAUTHENTICATED',

    #: The i8n message of ``UNAUTHORIZED``.
    #: Default: ``'UNAUTHORIZED'``.
    'MSG_UNAUTHORIZED': 'UNAUTHORIZED',

    #: The i8n message of ``Invalid Redirect Url``.
    #: Default: ``INVALID REDIRECT URL``.
    'MSG_INVALID_REDIRECT': 'INVALID REDIRECT URL',

    #: The i8n message of ``Anonymous User Required``.
    #: Default: ``ANONYMOUS USER REQUIRED``.
    'MSG_ANONYMOUS_USER_REQUIRED': 'ANONYMOUS USER REQUIRED'
}
