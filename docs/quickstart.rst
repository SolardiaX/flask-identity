Quick Start
===========

There are some complete (but simple) examples available in the *examples* directory of the
`Flask-Identity repo`_.

.. danger::
   The examples below place secrets in source files. Never do this for your application
   especially if your source code is placed in a public repo. How you pass in secrets
   securely will depend on your deployment model - however in most cases (e.g. docker, lambda)
   using environment variables will be the easiest.


* :ref:`basic-sqlalchemy-application`

.. _basic-sqlalchemy-application:

Basic SQLAlchemy Application
----------------------------

SQLAlchemy Install requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

     $ mkvirtualenv <your-app-name>
     $ pip install flask-identity flask-sqlalchemy


SQLAlchemy Application
~~~~~~~~~~~~~~~~~~~~~~

The following code sample illustrates how to get started as quickly as
possible using Flask-SQLAlchemy and the built-in model mixins:

::

    import os

    from flask import Flask, render_template_string
    from flask_sqlalchemy import SQLAlchemy
    from flask_identity import IdentityManager, auth_required, hash_password, UserMixin, RoleMixin

    # Create app
    app = Flask(__name__)
    app.config['DEBUG'] = True

    # Generate a nice key using secrets.token_urlsafe()
    app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", '2HF_R3JddWTLu0zJ1kSV-w')
    # Bcrypt is set as default SECURITY_PASSWORD_HASH, which requires a salt
    # Generate a good salt using: secrets.SystemRandom().getrandbits(128)
    app.config['IDENTITY_HASH_SALT'] = os.environ.get("IDENTITY_HASH_SALT", '2HF_R3JddWTLu0zJ1kSV_hash$salt_')
    app.config['IDENTITY_DATASTORE_ADAPTER']='sqlalchemy'

    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'
    # As of Flask-SQLAlchemy 2.4.0 it is easy to pass in options directly to the
    # underlying engine. This option makes sure that DB connections from the
    # pool are still valid. Important for entire application since
    # many DBaaS options automatically close idle connections.
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
    }

    # Create database connection object
    db = SQLAlchemy(app)

    # Define models

    class BaseModel(db.Model):
      __abstract__ = True

      id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    class Role(db.Model, RoleMixin):
        pass

    class User(db.Model, UserMixin):
        pass

    # Setup Flask-Identity
    identity = IdentityManager(app, db=db, user_model=Users, role_model=Roles)

    # Create a user to test with
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

    # Views
    @app.route("/")
    @auth_required()
    def home():
        return render_template_string("Hello {{ current_user.display }}")

    if __name__ == '__main__':
        app.run()

.. _Flask-Identity repo: https://github.com/solardiax/flask-identity
