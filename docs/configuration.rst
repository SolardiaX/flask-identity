Configuration
=============

The following configuration values are used by Flask-Identity.

Core
--------------

These configuration are used globally across all features.

.. py:data:: SECRET_KEY

    | This is actually part of Flask - but is used by Flask-Identity to sign all tokens.
    | It is critical this is set to a strong value.
    | For python3 consider using: ``secrets.token_urlsafe()``.

.. py:data:: IDENTITY_UNAUTHORIZED_VIEW

    | Specifies the view to redirect to if a user attempts to access a URL/endpoint
    | that they do not have permission to access.
    | If this value is ``None``, the user is presented with a default HTTP 403 response.
    |
    | Default: ``None``.

.. py:data:: IDENTITY_POST_LOGIN_VIEW

    | Specifies the default view to redirect to after a user logs in. This value can be set to a URL
    | or an endpoint name.
    |
    | Default: ``'/'``.

.. py:data:: IDENTITY_EXEMPT_METHODS

    | A set of HTTP methods which are exempt from `login_required`.
    |
    | Default: ``'OPTIONS'``.

.. py:data:: IDENTITY_IDENTITY_FIELD

    | The field used to lookup user from ``DataStore``.
    | The field must defined in ``UserMixin`` based user class.
    |
    | Default: ``'username'``.

.. py:data:: IDENTITY_TOKEN_FIELD

    | The field used to store user token in session or request.
    |
    | Default: ``'token'``.

.. py:data:: IDENTITY_REMEBER_FIELD

    | The form field used to mark whether enable "remember me".
    |
    | Default: ``'remember'``.

.. py:data:: IDENTITY_DEFAULT_REMEMBER_ME

    | Specifies the default "remember me" value used when logging in a user.
    |
    | Default: ``False``.

.. py:data:: IDENTITY_COOKIE_NAME

    | The name of the "remember me" cookie.
    |
    | Default: ``'remember_me'``.

.. py:data:: IDENTITY_COOKIE_DURATION

    | The default time before the "remember me" cookie expires.
    |
    | Default: ``365 days``.

.. py:data:: IDENTITY_COOKIE_SECURE

    | Whether the "remember me" cookie requires "Secure" attribute.
    |
    | Default: ``None``.

.. py:data:: IDENTITY_COOKIE_DOMAIN

    | The default domain name of the "remember me" cookie.
    |
    | Default: ``None``.

.. py:data:: IDENTITY_COOKIE_PATH

    | The default path of the "remember me" cookie.
    |
    | Default: ``'/'``.

.. py:data:: IDENTITY_COOKIE_HTTPONLY

    | Whether the "remember me" cookie uses HttpOnly or not.
    |
    | Default: ``False``.

.. py:data:: IDENTITY_COOKIE_REFRESH_EACH_REQUEST

    | Whether the "remember me" cookie will be refreshed by each request.
    |
    | Default: ``False``.

.. py:data:: IDENTITY_SESSION_USER_ID_KEY

    | The id used to identity user in session or cookie.
    |
    | Default: ``'user_id'``.

.. py:data:: IDENTITY_SESSION_PROTECTION

    | The mode to use session protection in.
    | This can be either ``'basic'`` (the default) or ``'strong'``, or ``None`` to disable it.
    |
    | Default: ``'basic'``.

.. py:data:: IDENTITY_SESSION_REMEBER_KEY

    | The key to store "remember" stats in session.
    |
    | Default: ``'remember'``.

.. py:data:: IDENTITY_SESSION_REMEBER_SECONDS_KEY

    | The key to store "remember_seconds" stats in session.
    |
    | Default: ``'remember_seconds'``.

.. py:data:: IDENTITY_SESSION_FRESH_KEY

    | The key to store "fresh" stats in session.
    |
    | Default: ``'_fresh'``.

.. py:data:: IDENTITY_SESSION_ID_KEY

    | The key to store session identity in session.
    |
    | Default: ``'_sid'``.

.. py:data:: IDENTITY_NEXT_STORE

    | The page the user is attempting to access is stored in the session
    | or a url parameter when redirecting to the login view; This can be either
    | ``'session'`` (the default) or ``'request'``.
    |
    | Default: ``'request'``.

.. py:data:: IDENTITY_NEXT_KEY

    | The key to store the url parameter when redirecting to the login view.
    |
    | Default: ``'_next'``.

.. py:data:: IDENTITY_TOKEN_SALT

    | The salt used to encrypt request or cookie token.
    | If this value is ``None`` (the default), then will use ``SECRET_KEY`` as salt
    | to encrypt token.
    |
    | Default: ``None``.

.. py:data:: IDENTITY_TOKEN_AUTHENTICATION_HEADER

    | The key to pass the token in HTTP request header.
    |
    | Default: ``'X-IdentityManager-Auth'``.

.. py:data:: IDENTITY_TOKEN_AUTHENTICATION_ARG

    | The parameter key to pass the token in HTTP request url.
    | If value exists in header and parameter, will use the url parameter as token.
    |
    | Default: ``'iauth'``.

.. py:data:: IDENTITY_HASH_SCHEMES

    | List of accepted password hashes.
    | See `Passlib CryptContext docs on Constructor Keyword 'schemes' <http://passlib.readthedocs.io/en/stable/lib/passlib.context.html?highlight=cryptcontext#constructor-keywords>`_
    | Example: ``['bcrypt', 'argon2']``:
    | Will create new hashes with 'bcrypt' and verifies existing hashes with 'bcrypt' and 'argon2'.
    |
    | Default: ``["bcrypt", "argon2", "des_crypt", "pbkdf2_sha256", "pbkdf2_sha512", "sha256_crypt", "sha512_crypt", "plaintext"]``.


.. py:data:: IDENTITY_HASH_OPTIONS

    | Dictionary of CryptContext keywords and hash options.
    | See `Passlib CryptContext docs on Constructor Keywords <http://passlib.readthedocs.io/en/stable/lib/passlib.context.html?highlight=cryptcontext#constructor-keywords>`_
    | and `Passlib CryptContext docs on Algorithm Options <http://passlib.readthedocs.io/en/stable/lib/passlib.context.html?highlight=cryptcontext#algorithm-options>`_
    |
    | Default: ``dict()``.

.. py:data:: IDENTITY_DATA_STORE

    | The custom identity data store to use. This can be either
    | ``'pony'`` (as default),
    | or a custom class implement from ``IdentityStore`` and ``Store``.
    |
    | Default: ``'pony'``.

Messages
--------------

These configuration are used to custom messages for i8n languages.

.. py:data:: IDENTITY_MSG_UNAUTHENTICATED

    | The i8n message of ``UNAUTHENTICATED``.
    |
    | Default: ``'UNAUTHENTICATED'``.

.. py:data:: IDENTITY_MSG_UNAUTHORIZED

    | The i8n message of ``UNAUTHORIZED``.
    |
    | Default: ``'UNAUTHORIZED'``.

.. py:data:: IDENTITY_MSG_INVALID_REDIRECT

    | The i8n message of ``Invalid Redirect Url``.
    |
    | Default: ``'INVALID REDIRECT URL'``.


.. py:data:: IDENTITY_MSG_ANONYMOUS_USER_REQUIRED

    | The i8n message of ``Anonymous User Required``.
    |
    | Default: ``'ANONYMOUS USER REQUIRED'``.
