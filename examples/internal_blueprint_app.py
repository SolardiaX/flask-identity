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

from flask import request, redirect, url_for, render_template

from flask_identity.decorators import roles_required
from flask_identity.utils import current_user, logout_user
from flask_identity.views import url_for_identity

from common import app
from common.models import *


app.config.update(
    IDENTITY_UNAUTHORIZED_VIEW=lambda: url_for_identity('login'),
    IDENTITY_BLUEPRINT_LOGIN_USER_TEMPLATE='user_login.html',
)


@app.route('/require_roles', methods=('GET', 'POST'))
@roles_required('admin')
def require_roles():
    if request.method == 'POST':
        logout_user()
        return redirect(url_for('require_roles'))

    return 'Roles required Page - %s you have roles: %s!' \
           % (current_user.display, ', '.join(r.display for r in current_user.roles)) \
           + '<form action="" method="post"><button type="submit">Logout</button></form>'


if __name__ == '__main__':
    db.init_app(app)
    db.create_all(app=app)

    identity.init_app(app, db=db, user_model=Users, role_model=Roles)
    app.run('0.0.0.0', 9000, True)
