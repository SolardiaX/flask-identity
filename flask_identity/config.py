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

    #: The identity field used to lookup user from ``DataStore``.
    #: The field must defined in ``UserMixin`` based user class.
    #: Default: ``'username'``.
    'IDENTITY_FIELD': 'username',

    #: The name used to store user token in request & session.
    #: Default: ``'token'``.
    'IDENTITY_TOKEN_NAME': 'token',

    #: Specifies whether should remember user when logging in.
    #: Default: ``False``.
    'REMEMBER_ME': False,

    #: The page the user is attempting to access is stored in the session
    #: or a url parameter when redirecting to the login view; This can be either
    #: ``'session'`` (the default) or ``'request'``.
    #: Default: ``'request'``.
    'NEXT_STORE': 'request',

    #: The key to store the source url when redirecting to the login view.
    #: The key will be used as url parameter in request or key in session.
    #: Default: ``'_next'``.
    'NEXT_KEY': '_next',

    #: Specifies the HMAC salt. This is required for all schemes that
    #: are configured for double hashing. A good salt can be generated using:
    #: ``secrets.SystemRandom().getrandbits(128)``.
    #: Defaults to ``None``.
    'HASH_SALT': None,

    #: The salt used to encrypt session, request or cookie token.
    #: If this value is ``None`` (the default), then will use ``SECRET_KEY`` as salt
    #: to encrypt token.
    #: Strongly recommend set it to a different value for more security.
    #: Default: ``None``.
    'TOKEN_SALT': None,

    #: The default time before the token expires.
    #: It's also used as the duration for "remember me" cookie.
    #: Default: ``365 days``.
    'TOKEN_DURATION': timedelta(days=365),

    #: The custom identity data store to use. This can be either ``'pony' | 'sqlalchemy' | 'mongoengine'``,
    #: or a custom class implement from ``IdentityStore`` and ``Store``.
    #: Default: ``None``
    'DATASTORE_ADAPTER': 'None',

    #: Specifies if Flask-Identity should track basic user login statistics.
    #: If set to ``True``, ensure your models have the required fields/attributes
    #: and make sure to commit changes after calling ``login_user``.
    #: Be sure to use `ProxyFix <http://flask.pocoo.org/docs/0.10/deploying/wsgi-standalone/#proxy-setups>`_
    #: if you are using a proxy.
    #: Defaults to ``False``
    'TRACKABLE': False,

    #: The form field used to mark whether enable "remember me".
    #: Default: ``'remember'``
    'FORM_REMEBER_FIELD': 'remember',

    #: The form field used to store the url parameter when redirecting to the login view.
    #: Default: ``'next'``
    'FORM_NEXT_FIELD': 'next',

    #: The name of the "remember me" cookie.
    #: Default: ``'remember_me'``.
    'COOKIE_NAME': 'remember_me',

    #: The session key to store cookie remember duration.
    #: It will be used when user login in.
    #: Default: ``'remember_seconds'``.
    'COOKIE_DURATION_SESSION_KEY': 'remember_seconds',

    #: The key to store "remember" stats in session.
    #: Default: ``'remember'``.
    'COOKIE_SESSION_STATE_KEY': 'remember',

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
    #: Default: ``False``.
    'COOKIE_REFRESH_EACH_REQUEST': False,

    #: The mode to use session protection in.
    #: This can be either ``'basic'`` (the default) or ``'strong'``, or ``None`` to disable it.
    #: Default: ``'basic'``.
    'SESSION_PROTECTION': 'basic',

    #: The key to store "fresh" stats in session.
    #: Default: ``'_fresh'``.
    'SESSION_FRESH_KEY': '_fresh',

    #: The key to store session identity in session.
    #: Default: ``'_sid'``.
    'SESSION_ID_KEY': '_sid',

    #: The key to pass the token in HTTP request header.
    #: Default: ``'X-Identity-Auth'``.
    'REQUEST_TOKEN_AUTHENTICATION_HEADER': 'X-Identity-Auth',

    #: The parameter key to pass the token in HTTP request url.
    #: Default: ``'iauth'``.
    'REQUEST_TOKEN_AUTHENTICATION_ARG': 'iauth',

    #: Specifies whether use build-in blueprint for user login and logout.
    #: Default: ``True``.
    'BLUEPRINT_ENABLED': True,

    #: Specifies the name for the build-in blueprint.
    #: Default: ``'identity'``.
    'BLUEPRINT_NAME': 'identity',

    #: Specifies the url prefix for the build-in blueprint.
    #: Default: ``'/identity'``.
    'BLUEPRINT_URL_PREFIX': '/identity',

    #: Specifies the sub domain for the build-in blueprint.
    #: Default: ``None``.
    'BLUEPRINT_SUBDOMAIN': None,

    #: Specifies the templates folder for the build-in blueprint.
    #: Default: ``'templates'``.
    'BLUEPRINT_TEMPLATE_FOLDER': 'templates',

    #: Specifies the "login" url for the build-in blueprint.
    #: Default: ``'/login'``.
    'BLUEPRINT_LOGIN_URL': '/login',

    #: Specifies the http method for the "login" url of the build-in blueprint.
    #: Default: ``['GET', 'POST']``.
    'BLUEPRINT_LOGIN_METHODS': ['GET', 'POST'],

    #: Specifies the "logout" url for the build-in blueprint.
    #: Default: ``'/logout'``.
    'BLUEPRINT_LOGOUT_URL': '/logout',

    #: Specifies the http method for the "logout" url of the build-in blueprint.
    #: Default: ``['GET', 'POST']``.
    'BLUEPRINT_LOGOUT_METHODS': ['GET', 'POST'],

    #: Specifies the template name for the "login" of the build-in blueprint.
    #: Default: ``'user_login.html'``.
    'BLUEPRINT_LOGIN_USER_TEMPLATE': 'user_login.html',

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

    #: A set of HTTP methods which are exempt from `login_required`.
    #: Default: ``'OPTIONS'``.
    'EXEMPT_METHODS': ['OPTIONS'],

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
