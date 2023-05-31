# -*- coding: utf-8 -*-

"""
    examples.common
    ~~~~~~~~~~~~~~~~~~~
    Common module of Simple Example of Flask-Identity

    :copyright: (c) 2019 by DreamEx Works.
    :license: MIT, see LICENSE for more details.
"""

import os

from flask import Flask


app = Flask('Flask-Identity-Examples', root_path=os.getcwd())
app.config.update(
    SECRET_KEY="2HF_R3JddWTLu0zJ1kSV-w",

    IDENTITY_HASH_SALT='2HF_R3JddWTLu0zJ1kSV_hash$salt_',
    IDENTITY_TOKEN_SALT='2HF_R3JddWTLu0zJ1kSV_token$salt_',
    IDENTITY_DATASTORE_ADAPTER='sqlalchemy',

    SQLALCHEMY_DATABASE_URI='sqlite://',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},

    BABEL_DEFAULT_LOCALE="zh_hans_CN",
)


def init():
    from flask_identity.utils import hash_password
    from common.models import babel, db, identity, Users, Roles

    babel.init_app(app)

    db.init_app(app)
    db.create_all()

    identity.init_app(app, db=db, user_model=Users, role_model=Roles)

    datastore = identity.datastore
    admin = datastore.find_user(username='admin')
    role = datastore.find_role(name='admin')
    if admin is None:
        admin = datastore.create_user(**{'username': 'admin', 'password': hash_password('123456'), 'display': 'Admin'})
    if role is None:
        role = datastore.create_role(**{'name': 'admin', 'display': 'Admin'})

    if admin and not admin.has_roles('admin'):
        datastore.add_role_to_user(admin, role)
