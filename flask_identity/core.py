# -*- coding: utf-8 -*-

"""
    identity.core
    ~~~~~~~~~~~~~~~~~~~
    The core methods of Flask-Identity

    :author: solardiax <solardiax@hotmail.com>
    :copyright: (c) 2020 by DreamEx Works.
    :license: GPL-3.0, see LICENSE for more details.
"""

import logging

from datetime import datetime, timedelta
from hashlib import sha512
from inspect import isclass

# noinspection PyProtectedMember
from flask import _request_ctx_stack, request, session, redirect, abort, render_template
from werkzeug.routing import BuildError

from ._hash_context import HashContext
from ._token_context import TokenContext
from .datastore import IdentityStore
from .config import default_config
from .mixins import AnonymousUserMixin
from .utils import get_config, get_url, get_user, clear_cookie, base64_encode_param
from .views import render_json, url_for_identity, create_blueprint

logger = logging.getLogger(__name__)


class IdentityManager(object):
    """
    Simple & Customizable User Authentication and Management.
    """

    def __init__(self, app=None, db=None, user_model=None, role_model=None, register_blueprint=None, **kwargs):
        """
        Init IdentityManager with `Flask(app)`, db, user_model and role_model

        :param app: `Flask(app)` instance
        :param db: An orm database instance.
        :param user_model: The model class of user
        :param role_model: The model class of role
        :param register_blueprint: Register default blueprint
        :param anonymous_user: The class of AnonymousUser based on ``AnonymousUserMixin``
        """
        self.app = app
        self._config = {}
        self._context_processors = {}
        self._anonymous_user = AnonymousUserMixin
        self._kwargs = kwargs
        self._register_blueprint = register_blueprint
        self._datastore = None
        self._token_context = None
        self._hash_context = None
        self._unauthz_handler = None
        self._unauthn_handler = None
        self._template_render = render_template

        if app is not None and user_model is not None and role_model is not None:
            self.init_app(app, db, user_model, role_model, register_blueprint, **kwargs)

    def __getattr__(self, name):
        if name.upper().startswith('CONFIG_'):
            return self._config.get(name.upper(), None)

        return None

    # noinspection PyIncorrectDocstring
    def init_app(self, app, db=None, user_model=None, role_model=None, register_blueprint=None, **kwargs):
        """
        Init IdentityManager with `Flask(app)`, db, user_model and role_model

        :param app: `Flask(app)` instance
        :param db: A database instance
        :param user_model: The model class of user
        :param role_model: The model class of role
        :param register_blueprint: Register default blueprint
        :param anonymous_user: The class of AnonymousUser based on ``AnonymousUserMixin``
        """
        if db is None:
            raise Exception("Missing db for Identity.")
        if user_model is None:
            raise Exception("Missing user_model for Identity.")
        if role_model is None:
            raise Exception("Missing role_model for Identity.")
        if register_blueprint is None:
            register_blueprint = self._register_blueprint

        for key, value in self._kwargs.items():
            kwargs.setdefault(key, value)

        for key, value in default_config.items():
            app.config.setdefault('IDENTITY_' + key.upper(), value)

        for key, value in get_config(app).items():
            kwargs[key.upper()] = value

        for key, value in kwargs.items():
            if hasattr(self, key.lower()):
                setattr(self, key.lower(), value)

            self._config[key.upper()] = value

        delattr(self, '_kwargs')

        adapter = self._config['DATASTORE_ADAPTER']

        if adapter == 'pony':
            from .datastore import PonyIdentityStore
            self._datastore = PonyIdentityStore(db, user_model, role_model)
        elif adapter == 'sqlalchemy':
            from .datastore import SQLAlchemyIdentityStore
            self._datastore = SQLAlchemyIdentityStore(db, user_model, role_model)
        elif adapter == 'mongoengine':
            from .datastore import MongoEngineIdentityStore
            self._datastore = MongoEngineIdentityStore(db, user_model, role_model)
        if isclass(adapter):
            self._datastore = adapter(db, user_model, role_model)

        self._hash_context = HashContext(app)
        self._token_context = TokenContext(app)

        app.extensions['identity'] = self

        app.after_request(self._update_remember_cookie)
        app.context_processor(self._default_context_processor)

        self.app = app

        if register_blueprint is None:
            register_blueprint = self._config.get('BLUEPRINT_ENABLED', True)
            self._register_blueprint = register_blueprint

        if register_blueprint:
            create_blueprint(self, __name__, app.json_encoder)

    def _add_ctx_processor(self, endpoint, fn):
        group = self._context_processors.setdefault(endpoint, [])
        fn not in group and group.append(fn)

    def _run_ctx_processor(self, endpoint):
        rv = {}
        for g in [None, endpoint]:
            for fn in self._context_processors.setdefault(g, []):
                rv.update(fn())
        return rv

    def context_processor(self, endpoint, fn):
        self._add_ctx_processor(endpoint, fn)

    def unauthenticated_handler(self, fn):
        """
        Register a custom unauthenticated handler.
        :param fn: Custom unauthenticated function.
        """
        self._unauthn_handler = fn

    def unauthorized_handler(self, fn):
        """
        Register a custom unauthorized handler.
        :param fn: Custom unauthorized function.
        """
        self._unauthz_handler = fn

    def template_render(self, fn):
        """
        Register a custom template render function.
        :param fn: Custom template render function.
        """
        self._template_render = fn

    def render_template(self, *args, **kwargs):
        return self._template_render(*args, **kwargs)

    def config_value(self, name, default=None):
        return self._config.get(name, default)

    def get_current_user(self):
        """
        | Try load `UserMixin` based instance from session,
        | if failed then try load from cookie,
        | if failed then try load from request.
        | Failed return `AnonymousUserMixin` based instance.

        :return: `UserMixin` or `AnonymousUserMixin` based instance.
        """
        if self._datastore is None:
            raise Exception("Missing datastore for Identity.")

        # Check SESSION_PROTECTION
        if self._session_protection_failed():
            return self.update_request_context_with_user()

        user = None

        # Load user from Flask Session
        token = session.get(self._config['IDENTITY_TOKEN_NAME'])
        if token is not None:
            data = self._token_context.verify_token(token)
            if data is not None:
                user = self._load_user_from_datastore(
                    data[self._config['IDENTITY_FIELD']], data.get('uniquifier', None)
                )

        # Load user from Remember Me Cookie or Request Loader
        if user is None:
            cookie_name = self._config['COOKIE_NAME']
            has_cookie = (
                    cookie_name in request.cookies and session.get(self._config['COOKIE_SESSION_STATE_KEY']) != 'clear'
            )
            if has_cookie:
                cookie = request.cookies[cookie_name]
                user = self._load_user_from_cookie(cookie)
            else:
                # noinspection PyTypeChecker
                user = self._load_user_from_request(request)

        return self.update_request_context_with_user(user)

    def unauthenticated(self, header=None):
        """
        | If caller wants JSON - return 403
        | Otherwise - assume caller is html and redirect to ``IDENTITY_UNAUTHENTICATED_VIEW`` or 403
        """
        if self._unauthn_handler:
            return self._unauthn_handler()

        return self._unauth_response(
            msg=self._config['MSG_UNAUTHENTICATED'],
            view=self._config['UNAUTHENTICATED_VIEW'],
            code=403,
            header=header
        )

    def unauthorized(self, header=None):
        """
        | If caller wants JSON - return 401
        | Otherwise - assume caller is html and redirect to ``IDENTITY_UNAUTHORIZED_VIEW`` or 401
        """
        if self._unauthz_handler:
            return self._unauthz_handler()

        return self._unauth_response(
            msg=self._config['MSG_UNAUTHORIZED'],
            view=self._config['UNAUTHORIZED_VIEW'],
            code=401,
            header=header
        )

    def update_request_context_with_user(self, user=None):
        """
        :param user: User object
        :return: Store the given user as ctx.user.
        """
        ctx = _request_ctx_stack.top
        ctx.user = self._anonymous_user() if user is None else user

    @property
    def datastore(self) -> IdentityStore:
        """
        :return: The datastore of Identity Manager
        """
        return self._datastore

    def _load_user_from_datastore(self, identity_field, uniquifier=None):
        user = self._datastore.find_user(identity_field)
        if not user or not user.is_actived:
            return None
        if not uniquifier and user and hasattr(user, 'uniquifier') and getattr(user, 'uniquifier') != uniquifier:
            return None
        return user

    def _load_user_from_cookie(self, cookie):
        # noinspection PyBroadException
        try:
            data = self._token_context.verify_token(cookie, ttl=self._config['TOKEN_DURATION'])
            identity_id = data[self._config['IDENTITY_FIELD']]
            if identity_id is not None:
                user = self._load_user_from_datastore(identity_id, data.get('uniquifier', None))
                if user is not None:
                    session[self._config['IDENTITY_TOKEN_NAME']] = user.get_auth_token()
                    session[self._config['SESSION_FRESH_KEY']] = False
                    return user
        except Exception:
            pass

        return self._anonymous_user()

    def _load_user_from_request(self, req):
        header_key = self._config['REQUEST_TOKEN_AUTHENTICATION_HEADER']
        args_key = self._config['REQUEST_TOKEN_AUTHENTICATION_ARG']
        header_token = req.headers.get(header_key, None)
        token = req.args.get(args_key, header_token)
        if req.is_json:
            data = req.get_json(silent=True) or {}
            if isinstance(data, dict):
                token = data.get(args_key, token)

        # noinspection PyBroadException
        try:
            data = self._token_context.verify_token(token, ttl=self._config['TOKEN_DURATION'])
            identity_field = data[self._config['IDENTITY_FIELD']]
            user = self._load_user_from_datastore(identity_field, data.get('uniquifier', None))
            if user is not None:
                return user
        except Exception:
            pass

        return self._anonymous_user()

    # noinspection PyMethodMayBeStatic
    def _get_remote_addr(self):
        address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if address is not None:
            # An 'X-Forwarded-For' header includes a comma separated list of the
            # addresses, the first address being the actual remote address.
            address = address.encode('utf-8').split(b',')[0].strip()
        return address

    # noinspection PyMethodMayBeStatic
    def _session_identifier_generator(self):
        user_agent = request.headers.get('User-Agent')
        if user_agent is not None:
            user_agent = user_agent.encode('utf-8')
        base = '{0}|{1}'.format(self._get_remote_addr(), user_agent)
        h = sha512()
        h.update(base.encode('utf8'))
        return h.hexdigest()

    # noinspection PyUnresolvedReferences,PyProtectedMember
    def _session_protection_failed(self):
        sess = session._get_current_object()
        ident = self._session_identifier_generator()
        mode = self._config['SESSION_PROTECTION']

        if not mode or mode not in ['basic', 'strong']:
            return False

        # if the sess is empty, it's an anonymous user or just logged out
        # so we can skip this
        if ident != session.get(self._config['SESSION_ID_KEY'], None):
            if mode == 'basic' or sess.permanent:
                sess[self._config['SESSION_FRESH_KEY']] = False
                return False
            elif mode == 'strong':
                for k in _SESSION_KEYS:
                    sess.pop(k, None)

                sess[self._config['COOKIE_SESSION_STATE_KEY']] = 'clear'
                return True

        return False

    @staticmethod
    def _default_context_processor():
        return dict(current_user=get_user(), url_for_identity=url_for_identity)

    def _update_remember_cookie(self, response):
        # Don't modify the session unless there's something to do.
        remeber_key = self._config['COOKIE_SESSION_STATE_KEY']
        if remeber_key not in session and \
                self._config['COOKIE_REFRESH_EACH_REQUEST']:
            session[remeber_key] = 'set'

        if remeber_key in session:
            operation = session.pop(remeber_key, None)

            if operation == 'set' and self._config['IDENTITY_TOKEN_NAME'] in session:
                self._set_cookie(response)
            elif operation == 'clear':
                clear_cookie(response)

        return response

    def _set_cookie(self, response):
        # cookie settings
        cookie_name = self._config['COOKIE_NAME']
        domain = self._config['COOKIE_DOMAIN']
        path = self._config['COOKIE_PATH']

        secure = self._config['COOKIE_SECURE']
        httponly = self._config['COOKIE_HTTPONLY']
        cookie_duration_session_key = self._config['COOKIE_DURATION_SESSION_KEY']

        if cookie_duration_session_key in session:
            duration = timedelta(seconds=session[cookie_duration_session_key])
        else:
            duration = self._config['TOKEN_DURATION']

        # prepare data
        data = session[self._config['IDENTITY_TOKEN_NAME']]

        if isinstance(duration, int):
            duration = timedelta(seconds=duration)

        try:
            expires = datetime.utcnow() + duration
        except TypeError:
            raise Exception('Duration must be a datetime.timedelta, instead got: {0}'.format(duration))

        # actually set it
        response.set_cookie(cookie_name, value=data, expires=expires, domain=domain, path=path, secure=secure,
                            httponly=httponly)

    # noinspection PyMethodMayBeStatic
    def _unauth_response(self, msg, view, code, header, redirect_to='/'):
        if request.is_json:
            return render_json(msg, code, header)

        next_key = self._config['NEXT_KEY']

        if view:
            if callable(view):
                view = view()
            else:
                try:
                    if self._config['NEXT_STORE'] == 'session':
                        session[self._config['SESSION_ID_KEY']] = self._session_identifier_generator()
                        session[next_key] = base64_encode_param(request.url)
                        view = get_url(view)
                except BuildError:
                    view = None

            if request.referrer and not request.referrer.split("?")[0].endswith(request.path):
                redirect_to = request.referrer

            if isinstance(view, str):
                view = get_url(view, qparams={next_key: base64_encode_param(request.url)})

            return redirect(view or redirect_to)

        abort(code)
