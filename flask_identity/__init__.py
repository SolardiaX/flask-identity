#  Disclaimer & Copyright Notice
#
#   Project: Flask-Identity
#    Author: hchenam
#
#  Copyright (c) 2019 DreamEx Works, All rights reserved.

# -*- coding: utf-8 -*-

"""
    Flask-Identity
    ~~~~~~~~~~~~~~~~~~~
    A lightweight Identity Manager for Flask

    :copyright: (c) 2019 by DreamEx Works.
    :license: GPL-3.0, see LICENSE for more details.
"""

from .core import IdentityManager
from .decorators import auth_required, login_required, roles_accepted, roles_required
from .mixins import UserMixin, AnonymousUserMixin, RoleMixin
from .utils import hash_password, verify_password, login_user, logout_user

__version__ = "1.0.0"
__all__ = (
    "IdentityManager",
    "auth_required", "login_required", "roles_accepted", "roles_required",
    "UserMixin", "AnonymousUserMixin", "RoleMixin",
    "hash_password", "verify_password", "login_user", "logout_user"
)
