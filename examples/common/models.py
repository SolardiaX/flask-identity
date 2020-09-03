#  Disclaimer & Copyright Notice
#
#   Project: Flask-Identity
#    Author: hchenam
#
#  Copyright (c) 2020 DreamEx Works, All rights reserved.

# -*- coding: utf-8 -*-

"""
    examples.models
    ~~~~~~~~~~~~~~~~~~~
    Database Models of Simple Example of Flask-Identity
    
    :copyright: (c) 2019 by DreamEx Works.
    :license: GPL-3.0, see LICENSE for more details.
"""

from datetime import datetime

from pony.orm import Database, Required, Optional, Set

from flask_identity.core import IdentityManager
from flask_identity.mixins import UserMixin, RoleMixin

identity = IdentityManager()
db = Database()


class Users(db.Entity, UserMixin):
    _table_ = 'sys_users'

    username = Required(str, unique=True, max_len=50)
    display = Required(str, max_len=50)
    password = Required(str, max_len=64)
    active = Required(bool, default=True, sql_default=True)
    last_login_at = Optional(datetime)
    current_login_at = Optional(datetime)
    last_login_ip = Optional(str, max_len=50)
    current_login_ip = Optional(str, max_len=50)
    login_count = Optional(int, sql_default=0)
    roles = Set("Roles", table='sys_users_roles')


class Roles(db.Entity, RoleMixin):
    _table_ = 'sys_roles'

    name = Required(str, unique=True, max_len=10)
    display = Required(str, unique=True, max_len=50)
    users = Set("Users")
