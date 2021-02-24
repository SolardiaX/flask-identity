# -*- coding: utf-8 -*-

"""
    identity.decorators
    ~~~~~~~~~~~~~~~~~~~
    Decorators definition of Flask-Identity

    :author: solardiax <solardiax@hotmail.com>
    :copyright: (c) 2020 by DreamEx Works.
    :license: GPL-3.0, see LICENSE for more details.
"""

from collections import namedtuple
from functools import wraps

# noinspection PyProtectedMember
from flask import request, _request_ctx_stack
from werkzeug.local import LocalProxy

from .utils import config_value, current_identity, current_user, current_app

BasicAuth = namedtuple("BasicAuth", "username, password")

_csrf = LocalProxy(lambda: current_app.extensions["csrf"])


def _check_token():
    # noinspection PyProtectedMember
    user = current_identity._load_user_from_request(request)

    if user and user.is_authenticated:
        current_identity.update_request_context_with_user(user)
        return True

    return False


def auth_required(*auth_methods):
    """
    Decorator that protects endpoints through multiple mechanisms.

    Example::

        @app.route('/dashboard')
        @auth_required('token', 'session')
        def dashboard():
            return 'Dashboard'

    :param auth_methods: Specified mechanisms (token, session). If not specified
        then all current available mechanisms will be tried.

    Note that regardless of order specified - they will be tried in the following
    order: token, session.

    The first mechanism that succeeds is used, following that, depending on
    configuration.

    On authentication failure :meth:`.IdentityManager.unauthenticated` will be called.
    """
    login_mechanisms = {
        "token": lambda: _check_token(),
        "session": lambda: current_user.is_authenticated,
    }
    mechanisms_order = ["token", "session"]
    if not auth_methods:
        auth_methods = {"session", "token"}
    else:
        auth_methods = [am for am in auth_methods]

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            mechanisms = [
                (method, login_mechanisms.get(method))
                for method in mechanisms_order
                if method in auth_methods
            ]
            for method, mechanism in mechanisms:
                if mechanism and mechanism():
                    return fn(*args, **kwargs)

            return current_identity.unauthenticated()

        return decorated_view

    return wrapper


def login_required(view_function):
    """
    Ensure that the current user is logged in and authenticated before calling
    the actual view.

    For example::

        @app.route('/post')
        @login_required
        def post():
            pass

    .. Note ::

        Per `W3 guidelines for CORS preflight requests
        <http://www.w3.org/TR/cors/#cross-origin-request-with-preflight-0>`_,
        HTTP ``OPTIONS`` requests are exempt from login checks.

    :param view_function: The view function to decorate.
    :type view_function: function
    """
    @wraps(view_function)
    def decorated_view(*args, **kwargs):
        if request.method in config_value('EXEMPT_METHODS'):
            return view_function(*args, **kwargs)
        elif not current_user.is_authenticated:
            return current_identity.unauthorized()
        return view_function(*args, **kwargs)

    return decorated_view


def roles_required(*role_names):
    """
    This decorator ensures that the current user is logged in,
    and has *all* of the specified roles (AND operation).

    Example::

        @route('/escape')
        @roles_required('Special', 'Agent')
        def escape_capture():  # User must be 'Special' AND 'Agent'
            ...

    Calls unauthenticated_view() when the user is not logged in
    or when user is not actived.

    Calls unauthorized_view() when the user does not have the required roles.

    Calls the decorated view otherwise.
    """
    def wrapper(view_function):
        @wraps(view_function)    # Tells debuggers that is is a function wrapper
        def decorator(*args, **kwargs):
            # User must have the required roles
            if not current_user.is_actived or not current_user.has_roles(*role_names):
                # Redirect to the unauthorized page
                return current_identity.unauthorized()

            # It's OK to call the view
            return view_function(*args, **kwargs)

        return decorator

    return wrapper


def roles_accepted(*role_names):
    """
    This decorator ensures that the current user is logged in,
    and has *at least one* of the specified roles (OR operation).

    Example::

        @route('/edit_article')
        @roles_accepted('Writer', 'Editor')
        def edit_article():  # User must be 'Writer' OR 'Editor'
            ...

    Calls unauthenticated_view() when the user is not logged in
    or when user is not actived.

    Calls unauthorized_view() when the user does not have the required roles.

    Calls the decorated view otherwise.
    """
    # convert the list to a list containing that list.
    # Because roles_required(a, b) requires A AND B
    # while roles_required([a, b]) requires A OR B
    def wrapper(view_function):
        @wraps(view_function)  # Tells debuggers that is is a function wrapper
        def decorator(*args, **kwargs):
            # User must have the required roles
            # NB: roles_required would call has_roles(*role_names): ('A', 'B') --> ('A', 'B')
            # But: roles_accepted must call has_roles(role_names):  ('A', 'B') --< (('A', 'B'),)
            if not current_user.is_actived() or not current_user.has_roles(role_names):
                # Redirect to the unauthorized page
                return current_identity.unauthorized()

            # It's OK to call the view
            return view_function(*args, **kwargs)

        return decorator

    return wrapper


def unauth_csrf(fall_through=False):
    """Decorator for endpoints that don't need authentication
    but do want CSRF checks (available via Header rather than just form).
    This is required when setting *WTF_CSRF_CHECK_DEFAULT* = **False** since in that
    case, without this decorator, the form validation will attempt to do the CSRF
    check, and that will fail since the csrf-token is in the header (for pure JSON
    requests).

    This decorator does nothing unless Flask-WTF::CSRFProtect has been initialized.

    This decorator does nothing if *WTF_CSRF_ENABLED* == **False**.

    This decorator will always require CSRF if the caller is authenticated.

    This decorator will suppress CSRF if caller isn't authenticated and has set the
    *SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS* config variable.

    :param fall_through: if set to True, then if CSRF fails here - simply keep going.
        This is appropriate if underlying view is form based and once the form is
        instantiated, the csrf_token will be available.
        Note that this can mask some errors such as 'The CSRF session token is missing.'
        meaning that the caller didn't send a session cookie and instead the caller
        might get a 'The CSRF token is missing.' error.
    """

    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            if not current_app.config.get("WTF_CSRF_ENABLED", False) or not current_app.extensions.get("csrf", None):
                return fn(*args, **kwargs)

            if config_value("CSRF_IGNORE_UNAUTH_ENDPOINTS") and not current_user.is_authenticated:
                _request_ctx_stack.top.fs_ignore_csrf = True
            else:
                try:
                    _csrf.protect()
                except:
                    if not fall_through:
                        raise

            return fn(*args, **kwargs)

        return decorated

    return wrapper
