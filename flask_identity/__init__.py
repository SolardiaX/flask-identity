# -*- coding: utf-8 -*-

"""
    Flask-Identity
    ~~~~~~~~~~~~~~~~~~~
    A lightweight Identity Manager for Flask

    :author: solardiax <solardiax@hotmail.com>
    :copyright: (c) 2020 by DreamEx Works.
    :license: GPL-3.0, see LICENSE for more details.
"""

from .core import IdentityManager
from .decorators import auth_required, login_required, roles_accepted, roles_required
from .mixins import UserMixin, AnonymousUserMixin, RoleMixin
from .utils import hash_password, verify_password, login_user, logout_user, current_user, current_identity
from .views import url_for_identity

__version__ = "1.0.0"
__all__ = (
    "IdentityManager",
    "auth_required", "login_required", "roles_accepted", "roles_required",
    "UserMixin", "AnonymousUserMixin", "RoleMixin",
    "hash_password", "verify_password", "login_user", "logout_user",
    "url_for_identity",
    "current_identity", "current_user"
)
