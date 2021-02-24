# -*- coding: utf-8 -*-

"""
    identity.views
    ~~~~~~~~~~~~~~~~~~~
    Default views of Flask-Identity
    
    :author: solardiax <solardiax@hotmail.com>
    :copyright: (c) 2020 by DreamEx Works.
    :license: GPL-3.0, see LICENSE for more details.
"""

from flask import request, after_this_request, jsonify, url_for, Blueprint
from flask_wtf import csrf
from werkzeug.datastructures import MultiDict

from .decorators import unauth_csrf
from .compats import get_quart_status
from .utils import (
    current_user,
    current_identity,
    login_user,
    logout_user,
    json_error_response,
    config_value,
    get_post_login_redirect,
    get_post_logout_redirect
)

if get_quart_status():
    # noinspection PyUnresolvedReferences,PyPackageRequirements
    from quart import make_response, redirect

    async def _commit(response=None):
        current_identity.datastore.commit()
        return response
else:
    from flask import make_response, redirect

    def _commit(response=None):
        current_identity.datastore.commit()
        return response


def _ctx(endpoint):
    # noinspection PyProtectedMember
    return current_identity._run_ctx_processor(endpoint)


def url_for_identity(endpoint, **values):
    """
    Return a URL for the Flask-Identity blueprint.

    This is method is a wrapper of :meth:``Flask.url_for``.

    :param endpoint: the endpoint of the URL (name of the function)
    :param values: the variable arguments of the URL rule
    """
    blueprint_name = current_identity.config_value('BLUEPRINT_NAME')
    if blueprint_name is None:
        raise RuntimeError('Blueprint not registed!')

    return url_for(f"{blueprint_name}.{endpoint}", **values)


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


def render_form_json_response(form, user, include_auth_token=False, error_status_code=400, additional=None):
    has_errors = len(form.errors) > 0
    if has_errors:
        code = error_status_code
        payload = json_error_response(errors=form.errors)
    else:
        code = 200
        payload = dict()
        if user:
            # This allows anonymous GETs via JSON
            payload["user"] = user.get_security_payload()

            if include_auth_token:
                token = user.get_auth_token()
                payload["user"]["authentication_token"] = token

        # Return csrf_token on each JSON response - just as every form
        # has it rendered.
        payload["csrf_token"] = csrf.generate_csrf()
        if additional:
            payload.update(additional)

    return render_json(payload, code, None)


@unauth_csrf(fall_through=True)
def login():
    """
    View function for login view

    Allow already authenticated users. For GET this is useful for
    single-page-applications on refresh - session still active but need to
    access user info and csrf-token.
    For POST - redirects to POST_LOGIN_VIEW (forms) or returns 400 (json).
    """
    if current_user.is_authenticated and request.method == "POST":
        # Just redirect current_user to POST_LOGIN_VIEW (or next).
        # While its tempting to try to logout the current user and login the
        # new requested user - that simply doesn't work with CSRF.
        if request.is_json:
            return render_json(config_value('MSG_ANONYMOUS_USER_REQUIRED'), 400, None)
        else:
            return redirect(get_post_login_redirect())

    form_class = current_identity.login_form
    if form_class is None:
        from .forms import LoginForm
        form_class = LoginForm

    if request.is_json:
        if request.content_length:
            form = form_class(MultiDict(request.get_json()))
        else:
            form = form_class(MultiDict([]))
    else:
        form = form_class(request.form)

    if form.validate_on_submit():
        remember_me = form.remember.data if config_value('FORM_REMEBER_FIELD') in form else None
        login_user(form.user, remember=remember_me)
        after_this_request(_commit)

        if not request.is_json:
            return redirect(get_post_login_redirect())

    if request.is_json:
        user = current_user if current_user.is_authenticated else None
        # noinspection PyTypeChecker
        return render_form_json_response(form, user, include_auth_token=True)

    if current_user.is_authenticated:
        # Basically a no-op if authenticated - just perform the same
        # post-login redirect as if user just logged in.
        return redirect(get_post_login_redirect())
    else:
        return current_identity.render_template(
            config_value("BLUEPRINT_LOGIN_USER_TEMPLATE"), login_form=form, **_ctx("login")
        )


@unauth_csrf(fall_through=True)
def logout():
    """
    View function which handles a logout request.
    """

    if current_user.is_authenticated:
        logout_user()

    # No body is required - so if a POST and json - return OK
    if request.method == "POST" and request.is_json:
        return render_json({}, 200, headers=None)

    return redirect(get_post_logout_redirect())


def create_blueprint(identity, import_name, json_encoder=None):
    """Creates the identity extension blueprint"""

    bp = Blueprint(
        identity.config_value('BLUEPRINT_NAME'),
        import_name,
        url_prefix=identity.config_value('BLUEPRINT_URL_PREFIX'),
        subdomain=identity.config_value('BLUEPRINT_SUBDOMAIN'),
        template_folder=identity.config_value('BLUEPRINT_TEMPLATE_FOLDER'),
    )

    if json_encoder:
        bp.json_encoder = json_encoder

    bp.route(identity.config_value('BLUEPRINT_LOGIN_URL'),
             methods=identity.config_value('BLUEPRINT_LOGIN_METHODS'), endpoint="login")(login)

    bp.route(identity.config_value('BLUEPRINT_LOGOUT_URL'),
             methods=identity.config_value('BLUEPRINT_LOGOUT_METHODS'), endpoint="logout")(logout)

    identity.app.register_blueprint(bp)
