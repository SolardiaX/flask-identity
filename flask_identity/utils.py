# -*- coding: utf-8 -*-

"""
    identity.utils
    ~~~~~~~~~~~~~~~~~~~
    Utils of Flask-Identity

    :author: solardiax <solardiax@hotmail.com>
    :copyright: (c) 2020 by DreamEx Works.
    :license: GPL-3.0, see LICENSE for more details.
"""

from datetime import datetime
from urllib.parse import parse_qsl, urlsplit, urlunsplit, urlencode

# noinspection PyProtectedMember
from flask import current_app, has_request_context, request, session, url_for, _request_ctx_stack
from itsdangerous import base64_decode, base64_encode
from werkzeug.local import LocalProxy

from .mixins import UserMixin

current_user = LocalProxy(lambda: get_user())
current_identity = LocalProxy(lambda: current_app.extensions['identity'])


def login_user(user: UserMixin, uniquifier=None, remember=None, duration=None, fresh=True):
    """
    Logs a user in. You should pass the actual user object to this. If the
    user's `is_active` property is ``False``, they will not be logged in
    unless `force` is ``True``.

    This will return ``True`` if the log in attempt succeeds, and ``False`` if
    it fails (i.e. because the user is inactive).

    :param user: The user object to log in.
    :type user: object
    :param uniquifier: The uniquifier for isolate login session. If ``None`` will
        use a ``uuid.hex()`` as default. Defatuls to ``None``.
    :type uniquifier: str
    :param remember: Whether to remember the user after their session expires.
        Defaults to ``IDENTITY_REMEMBER_ME``.
    :type remember: bool
    :param duration: The amount of time before the remember cookie expires. If
        ``None`` the value set in the settings is used. Defaults to ``None``.
    :type duration: :class:`datetime.timedelta`
    :param fresh: setting this to ``False`` will log in the user with a session
        marked as not "fresh". Defaults to ``True``.
    :type fresh: bool
    """
    if not user.is_actived:
        return False

    if config_value('TRACKABLE'):
        remote_addr = request.remote_addr or None  # make sure it is None

        old_current_login, new_current_login = (
            user.current_login_at,
            datetime.now()
        )
        old_current_ip, new_current_ip = user.current_login_ip, remote_addr

        user.last_login_at = old_current_login or new_current_login
        user.current_login_at = new_current_login
        user.last_login_ip = old_current_ip
        user.current_login_ip = new_current_ip
        user.login_count = user.login_count + 1 if user.login_count else 1

        current_identity.datastore.save(user)

    if hasattr(user, 'uniquifier'):
        current_identity.datastore.set_uniquifier(user, uniquifier)

    user_id = getattr(user, config_value('IDENTITY_FIELD'))
    remember = config_value('REMEMBER_ME') if remember is None else remember

    # noinspection PyProtectedMember
    session[config_value('IDENTITY_TOKEN_NAME')] = user.get_auth_token()

    # noinspection PyProtectedMember
    session[config_value('SESSION_ID_KEY')] = current_identity._session_identifier_generator()
    session[config_value('SESSION_FRESH_KEY')] = fresh

    if remember:
        session[config_value('COOKIE_SESSION_STATE_KEY')] = 'set'
        duration = config_value('TOKEN_DURATION') if duration is None else duration
        try:
            session[config_value('COOKIE_DURATION_SESSION_KEY')] = duration.total_seconds()
        except AttributeError:
            raise Exception('duration must be a datetime.timedelta, instead got: {0}'.format(duration))

    current_identity.update_request_context_with_user(user)

    return True


def logout_user():
    """
    Logs a user out. (You do not need to pass the actual user.) This will
    also clean up the remember me cookie if it exists.
    """
    id_key = config_value('IDENTITY_TOKEN_NAME')
    if id_key in session:
        session.pop(id_key)

    fresh = config_value('SESSION_FRESH_KEY')
    if fresh in session:
        session.pop(fresh)
    sid = config_value('SESSION_ID_KEY')
    if sid in session:
        session.pop(sid)

    cookie_name = config_value('COOKIE_NAME')
    if cookie_name in request.cookies:
        session[config_value('COOKIE_SESSION_STATE_KEY')] = 'clear'
        remember_seconds = config_value('COOKIE_DURATION_SESSION_KEY')
        if remember_seconds in session:
            session.pop(remember_seconds)

    current_identity.update_request_context_with_user()

    return True


def base64_encode_param(endpoint_or_url, qparams=None):
    param = get_url(endpoint_or_url, qparams)
    return base64_encode(param).decode('utf-8')


def base64_decode_param(param):
    return param if not param else base64_decode(param).decode('utf-8')


# noinspection PyBroadException
def get_url(endpoint_or_url, qparams=None):
    """
    Returns a URL if a valid endpoint is found. Otherwise, returns the
    provided value.

    :param endpoint_or_url: The endpoint name or URL to default to
    :param qparams: additional query params to add to end of url
    :return: URL
    """
    try:
        return transform_url(url_for(endpoint_or_url), qparams)
    except Exception:
        return transform_url(endpoint_or_url, qparams)


# noinspection PyProtectedMember
def transform_url(url, qparams=None, **kwargs):
    """ Modify url

    :param url: url to transform (can be relative)
    :param qparams: additional query params to add to end of url
    :param kwargs: pieces of URL to modify - e.g. netloc=localhost:8000
    :return: Modified URL

    .. versionadded:: 3.2.0
    """
    if not url:
        return url
    link_parse = urlsplit(url)
    if qparams:
        current_query = dict(parse_qsl(link_parse.query))
        current_query.update(qparams)
        link_parse = link_parse._replace(query=urlencode(current_query))
    return urlunsplit(link_parse._replace(**kwargs))


def validate_redirect_url(url):
    if url is None or url.strip() == "":
        return False
    url_next = urlsplit(url)
    url_base = urlsplit(request.host_url)
    if (url_next.netloc or url_next.scheme) and url_next.netloc != url_base.netloc:
        return False
    return True


def json_error_response(errors):
    """
    Helper to create an error response that adheres to the openapi spec.
    """
    if isinstance(errors, str):
        # When the errors is a string, use the response/error/message format
        response_json = dict(error=errors)
    elif isinstance(errors, dict):
        # When the errors is a dict, use the DefaultJsonErrorResponse
        # (response/errors/name/messages) format
        response_json = dict(errors=errors)
    else:
        raise TypeError("The errors argument should be either a str or dict.")

    return response_json


def get_post_action_redirect(config_key, declared=None):
    next_key = config_value('NEXT_KEY')
    next_field = config_value('FORM_NEXT_FIELD')

    urls = [
        base64_decode_param(get_url(request.args.get(next_key, None))),
        base64_decode_param(get_url(request.form.get(next_field, None))),
        base64_decode_param(get_url(session.get(next_key, None))),
        find_redirect("IDENTITY_" + config_key),
    ]

    if declared:
        urls.insert(0, declared)
    for url in urls:
        if validate_redirect_url(url):
            return url


def get_post_login_redirect(declared=None):
    return get_post_action_redirect("POST_LOGIN_VIEW", declared)


def get_post_logout_redirect(declared=None):
    return get_post_action_redirect("POST_LOGOUT_VIEW", declared)


def find_redirect(key):
    """
    Returns the URL to redirect to after a user logs in successfully.

    :param key: The session or application configuration key to search for
    """
    rv = (
        get_url(session.pop(key.lower(), None))
        or get_url(current_app.config[key.upper()] or None)
        or "/"
    )
    return rv


def config_value(key, app=None, default=None):
    """
    Get a Identity configuration value.

    :param key: The configuration key without the prefix `IDENTITY_`
    :param app: An optional specific application to inspect. Defaults to
                Flask's `current_app`
    :param default: An optional default value if the value is not set
    """
    app = app or current_app
    return get_config(app).get(key.upper(), default)


def get_config(app):
    """
    Conveniently get the security configuration for the specified
    application without the 'IDENTITY_' prefix.

    :param app: The `Flask` application to inspect
    """
    items = app.config.items()
    prefix = 'IDENTITY_'

    def strip_prefix(tup):
        return tup[0].replace('IDENTITY_', '', 1), tup[1]

    return dict([strip_prefix(i) for i in items if i[0].startswith(prefix)])


def hash_password(password):
    """
    Hash the specified plaintext password.
    :param password: The plaintext password to hash
    :return: The hashed password
    """
    # noinspection PyProtectedMember
    return current_identity._hash_context.hash_context(password)


def verify_password(password, password_hash):
    """
    Returns ``True`` if the password matches the supplied hash.

    :param password: A plaintext password to verify
    :param password_hash: The expected hash value of the password
                          (usually from your database)
    """
    # noinspection PyProtectedMember
    return current_identity._hash_context.verify_context(password, password_hash)


def clear_cookie(response):
    cookie_name = config_value('COOKIE_NAME')
    domain = config_value('COOKIE_DOMAIN')
    path = config_value('COOKIE_PATH')

    response.delete_cookie(cookie_name, domain=domain, path=path)


def get_user():
    if has_request_context() and not hasattr(_request_ctx_stack.top, 'user'):
        current_identity.get_current_user()

    return getattr(_request_ctx_stack.top, 'user', None)
