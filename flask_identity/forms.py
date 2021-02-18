# -*- coding: utf-8 -*-

"""
    identity.forms
    ~~~~~~~~~~~~~~~~~~~
    Default forms of Flask-Identity
    
    :author: solardiax <solardiax@hotmail.com>
    :copyright: (c) 2020 by DreamEx Works.
    :license: GPL-3.0, see LICENSE for more details.
"""

from flask import flash, request, session
from flask_wtf import FlaskForm
from wtforms import HiddenField, PasswordField, StringField, BooleanField, ValidationError
from wtforms.validators import DataRequired
from .utils import validate_redirect_url, config_value, current_identity, hash_password


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
    next = HiddenField()

    # noinspection PyMethodMayBeStatic
    def validate_next(self, field):
        if field.data and not validate_redirect_url(field.data):
            field.data = ""
            flash(config_value("MSG_INVALID_REDIRECT"))
            raise ValidationError(config_value("MSG_INVALID_REDIRECT"))


_IDENTITY_FIELD = config_value('IDENTITY_FIELD')
_REMEBER_FIELD = config_value('FORM_REMEBER_FIELD')
_NEXT_FIELD = config_value('FORM_NEXT_FIELD')


class LoginForm(BaseForm, NextFormMixin):
    """
    The default login form
    """
    locals()[_IDENTITY_FIELD] = StringField(_IDENTITY_FIELD, validators=[DataRequired()], default='')
    locals()[_REMEBER_FIELD] = BooleanField(_REMEBER_FIELD)
    locals()[_NEXT_FIELD] = HiddenField(_NEXT_FIELD)

    password = PasswordField('password', validators=[DataRequired()], default='')

    def __init__(self, *args, **kwargs):
        self.user = None
        self.next_url = None
        super().__init__(*args, **kwargs)

        if not self.next.data:
            next_key = config_value('NEXT_KEY')
            if config_value('NEXT_STORE') == 'request':
                getattr(self, _NEXT_FIELD).data = request.args.get(next_key, "")
            else:
                getattr(self, _NEXT_FIELD).data = session.get(next_key, "")

        getattr(self, _REMEBER_FIELD).default = config_value("DEFAULT_REMEMBER_ME")

    def validate(self):
        if not super().validate():
            return False

        self.user = current_identity.datastore.find_user(**{_IDENTITY_FIELD: self.data[_IDENTITY_FIELD]})

        if self.user is None:
            getattr(self, _IDENTITY_FIELD).errors.append('USER_DOES_NOT_EXIST')
            hash_password(self.password.data)

            return False

        return True
