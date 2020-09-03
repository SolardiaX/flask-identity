#  Disclaimer & Copyright Notice
#
#   Project: Flask-Identity
#    Author: hchenam
#
#  Copyright (c) 2019 DreamEx Works, All rights reserved.

# -*- coding: utf-8 -*-

"""
    identity.utils
    ~~~~~~~~~~~~~~~~~~~
    Utils of Flask-Identity

    :copyright: (c) 2019 by DreamEx Works.
    :license: GPL-3.0, see LICENSE for more details.
"""

# noinspection PyProtectedMember
from flask import current_app, has_request_context, make_response, request, jsonify, session, url_for, \
    _request_ctx_stack
from urllib.parse import parse_qsl, parse_qs, urlsplit, urlunsplit, urlencode
from werkzeug.local import LocalProxy
from .mixins import UserMixin

current_user = LocalProxy(lambda: _get_user())
current_identity = LocalProxy(lambda: current_app.extensions['identity'])


def login_user(user: UserMixin, remember=False, duration=None, fresh=True):
    """
    Logs a user in. You should pass the actual user object to this. If the
    user's `is_active` property is ``False``, they will not be logged in
    unless `force` is ``True``.

    This will return ``True`` if the log in attempt succeeds, and ``False`` if
    it fails (i.e. because the user is inactive).

    :param user: The user object to log in.
    :type user: object
    :param remember: Whether to remember the user after their session expires.
        Defaults to ``False``.
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

    user_id = getattr(user, config_value('IDENTITY_FIELD'))

    # noinspection PyProtectedMember
    session[config_value('SESSION_USER_ID_KEY')] = current_identity._token_context.generate_token(
        **{config_value('IDENTITY_FIELD'): user_id}
    )

    # noinspection PyProtectedMember
    session[config_value('SESSION_ID_KEY')] = current_identity._session_identifier_generator()
    session[config_value('SESSION_FRESH_KEY')] = fresh

    if remember:
        session[config_value('SESSION_REMBER_KEY')] = 'set'
        if duration is not None:
            try:
                session[config_value('SESSION_REMBER_SECONDS_KEY')] = duration.total_seconds()
            except AttributeError:
                raise Exception('duration must be a datetime.timedelta, instead got: {0}'.format(duration))

    current_identity.update_request_context_with_user(user)

    return True


def logout_user():
    """
    Logs a user out. (You do not need to pass the actual user.) This will
    also clean up the remember me cookie if it exists.
    """
    id_key = config_value('SESSION_USER_ID_KEY')
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
        session[config_value('SESSION_REMBER_KEY')] = 'clear'
        remember_seconds = config_value('SESSION_REMBER_SECONDS_KEY')
        if remember_seconds in session:
            session.pop(remember_seconds)

    current_identity.update_request_context_with_user()

    return True


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


def render_json(payload, code, headers):
    """
    Default JSON response handler.
    """
    # Force Content-Type header to json.
    if headers is None:
        headers = dict()
    headers["Content-Type"] = "application/json"
    payload = dict(meta=dict(code=code), response=payload)

    return make_response(jsonify(payload), code, headers)


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
    urls = [
        get_url(request.args.get("next", None)),
        get_url(request.form.get("next", None)),
        find_redirect(config_key),
    ]
    if declared:
        urls.insert(0, declared)
    for url in urls:
        if validate_redirect_url(url):
            return url


def get_post_login_redirect(declared=None):
    return get_post_action_redirect("IDENTITY_POST_LOGIN_VIEW", declared)


def get_post_logout_redirect(declared=None):
    return get_post_action_redirect("IDENTITY_POST_LOGOUT_VIEW", declared)


def get_post_verify_redirect(declared=None):
    return get_post_action_redirect("IDENTITY_POST_VERIFY_VIEW", declared)


def find_redirect(key):
    """Returns the URL to redirect to after a user logs in successfully.

    :param key: The session or application configuration key to search for
    """
    rv = (
        get_url(session.pop(key.lower(), None))
        or get_url(current_app.config[key.upper()] or None)
        or "/"
    )
    return rv


def propagate_next(url):
    # return either URL or, if URL already has a ?next=xx, return that.
    url_next = urlsplit(url)
    qparams = parse_qs(url_next.query)
    if "next" in qparams:
        return qparams["next"][0]
    return url


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


def _clear_cookie(response):
    cookie_name = config_value('COOKIE_NAME')
    domain = config_value('COOKIE_DOMAIN')
    path = config_value('COOKIE_PATH')

    response.delete_cookie(cookie_name, domain=domain, path=path)


def _get_user():
    if has_request_context() and not hasattr(_request_ctx_stack.top, 'user'):
        current_identity.get_current_user()

    return getattr(_request_ctx_stack.top, 'user', None)
