Configuration
=============

The following configuration values are used by Flask-Identity.

Core
--------------

These configuration are used globally across all features and should be configurated in application.

.. py:data:: SECRET_KEY

    This is actually part of Flask - but is used by Flask-Identity to sign all tokens.
    It is critical this is set to a strong value.

    For python3 consider using: ``secrets.token_urlsafe()``

.. py:data:: UNAUTHORIZED_VIEW

    Specifies the view to redirect to if a user attempts to access a URL/endpoint that
    they do not have permission to access.
    If this value is ``None``, the user is presented with a default HTTP 403 response.

    Default: ``None``.

.. py:data:: POST_LOGIN_VIEW

    Specifies the default view to redirect to after a user logs in.
    This value can be set to a URL or an endpoint name.

    Default: ``'/'``.

.. py:data:: POST_LOGOUT_VIEW

    Specifies the default view to redirect to after a user logs out.
    This value can be set to a URL or an endpoint name.

    Default: ``'/'``.

.. py:data:: IDENTITY_TOKEN_NAME

    The name used to store user token in request & session.

    Default: ``'token'``.

.. py:data:: REMEMBER_ME

    Specifies whether should remember user when logging in.

    Default: ``False``.

.. py:data:: NEXT_STORE

    The page the user is attempting to access is stored in the session or
    a url parameter when redirecting to the login view.
    This can be either ``'session'`` (the default) or ``'request'``.

    Default: ``'request'``.

.. py:data:: NEXT_KEY

    The key to store the source url when redirecting to the The key will
    be used as url parameter in request or key in session.

    Default: ``'_next'``.

.. py:data:: HASH_SALT

    Specifies the HMAC salt. This is required for all schemes that
    are configured for double hashing. A good salt can be generated using:
    ``secrets.SystemRandom().getrandbits(128)``.

    If this value is ``None`` (the default), then will use ``SECRET_KEY`` as salt to encrypt hash.

    Strongly recommend set it to a different value for more security.
    
    Defaults to ``None``.

.. py:data:: TOKEN_SALT

    The salt used to encrypt session, request or cookie token.
    If this value is ``None`` (the default), then will use ``SECRET_KEY`` as salt to encrypt token.

    Strongly recommend set it to a different value for more security.

    Default: ``None``.

.. py:data:: TOKEN_DURATION

    The default time before the token expires.
    It's also used as the duration for "remember me" cookie.

    Default: ``365 days``.

.. py:data:: DATASTORE_ADAPTER

    The custom identity data store to use.
    This can be either ``'pony' | 'sqlalchemy' | 'mongoengine'``,
    or a custom class implement from ``IdentityStore`` and ``Store``.

    Default: ``None``.

.. py:data:: DATASTORE_IDENTITY_FIELD

    The identity field used to lookup user from ``DataStore``.
    The field must defined in ``UserMixin`` based user class.

    Default: ``'username'``.

.. py:data:: DATASTORE_UNIQUE_TOKEN_FIELD

    The identity field used to store unique token in ``DataStore``.
    This will immediately render outstanding auth tokens invalid.

    Default: ``uniquifier``.

.. py:data:: TRACKABLE

    Specifies if Flask-Identity should track basic user login statistics.
    If set to ``True``, ensure your models have the required fields/attributes
    and make sure to commit changes after calling ``login_user``.
    Be sure to use `ProxyFix <http://flask.pocoo.org/docs/0.10/deploying/wsgi-standalone/#proxy-setups>`_
    if you are using a proxy.

    Defaults to ``False``

Form
--------------

These configuration are used with build-in form to login in a user.

.. py:data:: FORM_IDENTITY_FIELD

    The form field used to store the identity login for lookup in `Datastore` with `"IDENTITY_FIELD"`.

    Default: ``'username'``

.. py:data:: FORM_REMEBER_FIELD

    The form field used to mark whether enable "remember me".

    Default: ``'remember'``.

.. py:data:: FORM_NEXT_FIELD

    The form field used to store the url parameter when redirecting to the login view.

    Default: ``'next'``.

Cookie
--------------

These configuration are used with cookie.

.. py:data:: COOKIE_NAME

    The name of the "remember me" cookie.

    Default: ``'remember_me'``.

.. py:data:: COOKIE_DURATION_SESSION_KEY

    The session key to store cookie remember duration. It will be used when user login in.

    Default: ``'remember_seconds'``.

.. py:data:: COOKIE_SESSION_STATE_KEY

    The key to store "remember" stats in session.

    Default: ``'remember'``.

.. py:data:: COOKIE_SECURE

    Whether the "remember me" cookie requires "Secure" attribute.

    Default: ``None``.

.. py:data:: COOKIE_DOMAIN

    The default domain name of the "remember me" cookie.

    Default: ``None``.

.. py:data:: COOKIE_PATH

    The default path of the "remember me" cookie.

    Default: ``'/'``.

.. py:data:: COOKIE_HTTPONLY

    Whether the "remember me" cookie uses HttpOnly or not.

    Default: ``False``.

.. py:data:: COOKIE_REFRESH_EACH_REQUEST

    Whether the "remember me" cookie will be refreshed by each request.

    Default: ``False``.

Session
--------------

These configuration are used with session.

.. py:data:: SESSION_PROTECTION

    The mode to use session protection in. This can be either ``'basic'`` (the default) or ``'strong'``,
    or ``None`` to disable it.

    Default: ``'basic'``.

.. py:data:: SESSION_FRESH_KEY

    The key to store "fresh" stats in session.

    Default: ``'_fresh'``.

.. py:data:: SESSION_ID_KEY

    The key to store session identity in session.

    Default: ``'_sid'``.

Request
--------------

These configuration are used with request.

.. py:data:: REQUEST_TOKEN_AUTHENTICATION_HEADER

    The key to pass the token in HTTP request header.

    Default: ``'X-Identity-Auth'``.

.. py:data:: REQUEST_TOKEN_AUTHENTICATION_ARG

    The parameter key to pass the token in HTTP request url.

    Default: ``'iauth'``.


Blueprint
--------------

These configuration are used with build-in flask blueprint.

.. py:data:: BLUEPRINT_ENABLED

    Specifies whether use build-in blueprint for user login and logout.

    Default: ``True``.

.. py:data:: BLUEPRINT_NAME

    Specifies the name for the build-in blueprint.

    Default: ``'identity'``.

.. py:data:: BLUEPRINT_URL_PREFIX

    Specifies the url prefix for the build-in blueprint.

    Default: ``'/identity'``.

.. py:data:: BLUEPRINT_SUBDOMAIN

    Specifies the sub domain for the build-in blueprint.

    Default: ``None``.

.. py:data:: BLUEPRINT_TEMPLATE_FOLDER

    Specifies the templates folder for the build-in blueprint.

    Default: ``'templates'``.

.. py:data:: BLUEPRINT_LOGIN_URL

    Specifies the "login" url for the build-in blueprint.

    Default: ``'/login'``.

.. py:data:: BLUEPRINT_LOGIN_METHODS

    Specifies the http method for the "login" url of the build-in blueprint.

    Default: ``['GET', 'POST']``.

.. py:data:: BLUEPRINT_LOGIN_USER_TEMPLATE

    Specifies the template name for the "login" of the build-in blueprint.

    Default: ``'user_login.html'``.

.. py:data:: BLUEPRINT_LOGOUT_URL

    Specifies the "logout" url for the build-in blueprint.

    Default: ``'/logout'``.

.. py:data:: BLUEPRINT_LOGOUT_METHODS

    Specifies the http method for the "logout" url of the build-in blueprint.

    Default: ``['GET', 'POST']``.

Misc
--------------

These configuration are rarely need change.

.. py:data:: HASH_SCHEMES

    List of accepted password hashes.
    See `Passlib CryptContext docs on Constructor Keyword 'schemes' <http://passlib.readthedocs.io/en/stable/lib/passlib.context.html?highlight=cryptcontext#constructor-keywords>`_

    Example: ``['bcrypt', 'argon2']``:
      Will create new hashes with 'bcrypt' and verifies existing hashes with 'bcrypt' and 'argon2'.

    Default: ``["bcrypt", "argon2", "des_crypt", "pbkdf2_sha256", "pbkdf2_sha512", "sha256_crypt", "sha512_crypt", "plaintext"]``.

.. py:data:: HASH_OPTIONS

    Dictionary of CryptContext keywords and hash options.
    See `Passlib CryptContext docs on Constructor Keywords <http://passlib.readthedocs.io/en/stable/lib/passlib.context.html?highlight=cryptcontext#constructor-keywords>`_
    and `Passlib CryptContext docs on Algorithm Options <http://passlib.readthedocs.io/en/stable/lib/passlib.context.html?highlight=cryptcontext#algorithm-options>`_

    Default: ``dict()``.

.. py:data:: EXEMPT_METHODS

    A set of HTTP methods which are exempt from `login_required`.

    Default: ``'OPTIONS'``.


Message
--------------

These configuration are used in i8n response messages.

.. py:data:: I18N_DOMAIN

    Specifies the name for domain used for translations.

    Default: ``'flask_identity'``.

.. py:data:: I18N_DIRNAME

    Specifies the directory containing the MO files used for translations.

    Default: ``[PATH_LIB]/flask_identity/translations``.


WTF/CSRF
--------------

.. py:data:: WTF_CSRF_ENABLED

    Flask-WTF: Set to False to disable all CSRF protection.

    Default: ``True``

.. py:data:: WTF_CSRF_CHECK_DEFAULT

    Flask-WTF: When using the CSRF protection extension, this controls whether every view is protected by default.

    Default: ``True``

.. py:data:: WTF_CSRF_SECRET_KEY

    Flask-WTF: Random data for generating secure tokens. If this is not set then SECRET_KEY is used.

    Default: ``None``

.. py:data:: WTF_CSRF_METHODS

    Flask-WTF: HTTP methods to protect from CSRF.

    Default is ``{'POST', 'PUT', 'PATCH', 'DELETE'}``

.. py:data:: WTF_CSRF_FIELD_NAME

    Flask-WTF: Name of the form field and session key that holds the CSRF token.

    Default: ``'csrf_token'``

.. py:data:: WTF_CSRF_HEADERS

    Flask-WTF: HTTP headers to search for CSRF token when it is not provided in the form.

    Default: ``['X-CSRFToken', 'X-CSRF-Token']``

.. py:data:: WTF_CSRF_TIME_LIMIT

    Flask-WTF: Max age in seconds for CSRF tokens.
    If set to None, the CSRF token is valid for the life of the session.

    Default: ``3600``

.. py:data:: WTF_CSRF_SSL_STRICT

    Flask-WTF: Whether to enforce the same origin policy by checking that the referrer matches the host.
    Only applies to HTTPS requests.

    Default: ``True``

.. py:data:: WTF_I18N_ENABLED

    Flask-WTF: Set to False to disable Flask-Babel I18N support.
    Also set to False if you want to use WTForms’s built-in messages directly.

    Default: ``True``

.. py:data:: WTF_CSRF_IGNORE_UNAUTH_ENDPOINTS

    Specifies the endpoint to ignore CSRF check.
    Default: ``[]``
