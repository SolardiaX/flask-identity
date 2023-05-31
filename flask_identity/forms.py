# -*- coding: utf-8 -*-

"""
    identity.forms
    ~~~~~~~~~~~~~~~~~~~
    Default forms of Flask-Identity
    
    :author: solardiax <solardiax@hotmail.com>
    :copyright: (c) 2020 by DreamEx Works.
    :license: MIT, see LICENSE for more details.
"""

from flask import flash, request, session
from flask_wtf import FlaskForm
from wtforms import HiddenField, PasswordField, StringField, BooleanField, ValidationError
from wtforms.validators import DataRequired
from .utils import validate_redirect_url, config_value, current_identity, get_message


class BaseForm(FlaskForm):
    def to_json(self, include_user=True, include_auth_token=False, additional=None):
        payload = dict()

        user = self.user if hasattr(self, "user") else None
        if user:
            if include_user:
                # noinspection PyUnresolvedReferences
                payload["user"] = user.get_security_payload()
            if include_auth_token:
                # noinspection PyUnresolvedReferences
                payload["user"]["authentication_token"] = user.get_auth_token()

        if additional:
            payload.update(additional)

        return payload


class NextFormMixin:
    def __init__(self, *args, **kwargs):
        self._NEXT_FIELD = config_value('FORM_NEXT_FIELD')
        setattr(NextFormMixin, self._NEXT_FIELD, HiddenField(self._NEXT_FIELD))

    # noinspection PyMethodMayBeStatic
    def validate_next(self, field):
        if field.data and not validate_redirect_url(field.data):
            field.data = ""
            flash(config_value("MSG_INVALID_REDIRECT"))
            raise ValidationError(config_value("MSG_INVALID_REDIRECT"))


class LoginForm(BaseForm, NextFormMixin):
    """
    The default login form
    """

    password = PasswordField('password', validators=[DataRequired()], default='')

    def __init__(self, *args, **kwargs):
        NextFormMixin.__init__(self, *args, **kwargs)

        self.user = None
        self.next_url = None

        self._IDENTITY_FIELD = config_value('IDENTITY_FIELD')
        self._REMEBER_FIELD = config_value('FORM_REMEBER_FIELD')

        _unbound_fields = set(self._unbound_fields)

        setattr(LoginForm, self._IDENTITY_FIELD,
                StringField(self._IDENTITY_FIELD, validators=[DataRequired()], default=''))
        setattr(LoginForm, self._REMEBER_FIELD, BooleanField(self._REMEBER_FIELD))

        _unbound_fields.add((self._IDENTITY_FIELD, getattr(self, self._IDENTITY_FIELD)))
        _unbound_fields.add((self._REMEBER_FIELD, getattr(self, self._REMEBER_FIELD)))
        _unbound_fields.add((self._NEXT_FIELD, getattr(self, self._NEXT_FIELD)))

        self._unbound_fields = list(_unbound_fields)

        BaseForm.__init__(self, *args, **kwargs)

        if not self.next.data:
            next_key = config_value('NEXT_KEY')
            if config_value('NEXT_STORE') == 'request':
                getattr(self, self._NEXT_FIELD).data = request.args.get(next_key, "")
            else:
                getattr(self, self._NEXT_FIELD).data = session.get(next_key, "")

        getattr(self, self._REMEBER_FIELD).default = config_value("DEFAULT_REMEMBER_ME")

    def validate(self, extra_validators=None):
        if not super().validate():
            return False

        self.user = current_identity.datastore.find_user(**{self._IDENTITY_FIELD: self.data[self._IDENTITY_FIELD]})

        if self.user is None:
            getattr(self, self._IDENTITY_FIELD).errors.append(get_message('USER_DOES_NOT_EXIST')[0])
            return False

        if not self.user.verify_password(self.password.data):
            self.password.errors.append(get_message('INVALID_PASSWORD')[0])
            return False

        if not self.user.is_actived:
            getattr(self, self._IDENTITY_FIELD).errors.append(get_message('DISABLED_ACCOUNT')[0])
            return False

        return True
