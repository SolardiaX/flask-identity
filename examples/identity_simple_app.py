#  Disclaimer & Copyright Notice
#
#   Project: Flask-Identity
#    Author: hchenam
#
#  Copyright (c) 2020 DreamEx Works, All rights reserved.

# -*- coding: utf-8 -*-

"""
    examples.app
    -----------
    Simple Example of Flask-Identity

    :copyright: (c) 2019 by DreamEx Works.
    :license: GPL-3.0, see LICENSE for more details.
"""

import os
import sys
from pathlib import Path

from flask import Flask, request, redirect, url_for
from pony.flask import Pony

from flask_identity.decorators import roles_required
from flask_identity.utils import hash_password, verify_password, current_user, login_user, logout_user
from common.models import *

app = Flask(__name__)


@app.route('/require_roles', methods=('GET', 'POST'))
@roles_required('admin')
def require_roles():
    if request.method == 'POST':
        logout_user()
        return redirect(url_for('require_roles'))

    return 'Roles required Page - %s you have roles: %s!' \
           % (current_user.display, ', '.join(r.display for r in current_user.roles)) \
           + '<form action="" method="post"><button type="submit">Logout</button></form>'


@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        datastore = identity.datastore
        user = datastore.find_user(username='admin')
        datastore.add_role_to_user(user, 'admin')
        if verify_password('123456', user.password):
            login_user(user)
            return redirect(url_for('require_roles'))

    return '<form action="" method="post"><input type="text" value="xxxx" name="dynamic">' \
           '<button type="submit">Login</button></form>'


@app.before_first_request
def init():
    datastore = identity.datastore
    admin = datastore.find_user(username='admin')
    role = datastore.find_role(name='admin')
    if admin is None:
        admin = datastore.create_user(**{'username': 'admin', 'password': hash_password('123456'), 'display': 'Admin'})
    if role is None:
        role = datastore.create_role(**{'name': 'admin', 'display': 'Admin'})

    if admin and not admin.has_roles('admin'):
        datastore.add_role_to_user(admin, role)


def create_app():
    application_path = os.getcwd()

    if getattr(sys, 'frozen', False):
        application_path = os.path.dirname(sys.executable)

    app.config.update(
        SECRET_KEY="2HF_R3JddWTLu0zJ1kSV-w",

        IDENTITY_HASH_SALT='2HF_R3JddWTLu0zJ1kSV_hash$salt_',
        IDENTITY_TOKEN_SALT='2HF_R3JddWTLu0zJ1kSV_token$salt_',
        IDENTITY_UNAUTHORIZED_VIEW='/login',

        PONY={
            'provider': 'sqlite',
            'filename': str(Path(application_path).joinpath('database.db')),
            'create_db': 'True',
        }
    )

    db.bind(**app.config['PONY'])
    db.generate_mapping(create_tables=True)

    Pony(app)
    identity.init_app(app, db=db, user_model=Users, role_model=Roles)

    return app


if __name__ == '__main__':
    a = create_app()
    a.run('0.0.0.0', 9000, True)
