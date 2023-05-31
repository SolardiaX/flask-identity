# -*- coding: utf-8 -*-

"""
    examples.app
    -----------
    Simple Example of Flask-Identity

    :copyright: (c) 2019 by DreamEx Works.
    :license: MIT, see LICENSE for more details.
"""

from flask import request, redirect, url_for, render_template

from flask_identity.decorators import roles_required
from flask_identity.utils import verify_password, current_user, login_user, logout_user, get_post_login_redirect
from flask_identity.forms import LoginForm

from common import app
from common.models import *


app.config.update(
    IDENTITY_UNAUTHORIZED_VIEW='/login'
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


@app.route('/login', methods=('GET', 'POST'))
def login():
    error = ''
    form = LoginForm()

    if form.validate_on_submit():
        datastore = identity.datastore
        user = datastore.find_user(username=request.values.get('username'))
        if user and verify_password(request.values.get('password'), user.password):
            login_user(user)
            return redirect(get_post_login_redirect())
        else:
            error = 'username/password error.'

    return render_template('user_login_api_only.html', error=error)


if __name__ == '__main__':
    babel.init_app(app)

    db.init_app(app)
    db.create_all(app=app)

    identity.init_app(app, db=db, user_model=Users, role_model=Roles)
    app.run('0.0.0.0', 9000, True)
