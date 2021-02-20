Models
======

Flask-Identity assumes you'll be using libraries such as SQLAlchemy or PonyORM
to define a data model that includes a `User` and `Role` model.
The fields on your models must follow a particular convention depending on
the functionality your app requires. Aside from this, you're free
to add any additional fields to your model(s) if you want.

As more features are added to Flask-Identity, the requirements for required fields and tables grow.
As you use these features, and therefore use these fields and tables, database migrations are required;
which are a bit of a pain. To make things easier - Flask-Identity includes mixins that
contain ALL the fields and tables required for all features. They also contain
various `best practice` fields - such as update and create times. These mixins can
be easily extended to add any sort of custom fields and can be found in the
`models` module (today there is just one for using Flask-SqlAlchemy).

At the bare minimum
your `User` and `Role` model should include the following fields:

**User**

* ``id``
* ``email``
* ``password``
* ``active``
* ``uniquifier``


**Role**

* ``id``
* ``name``
* ``description``


Additional Functionality
------------------------

Depending on the application's configuration, additional fields may need to be
added to your `User` model.

Trackable
^^^^^^^^^

If you enable user tracking by setting your application's `IDENTITY_TRACKABLE`
configuration value to `True`, your `User` model will require the following
additional fields:

* ``last_login_at``
* ``current_login_at``
* ``last_login_ip``
* ``current_login_ip``
* ``login_count``

Custom User Payload
^^^^^^^^^^^^^^^^^^^

If you want a custom payload for JSON API responses, define
the method `get_security_payload` in your User model. The method must return a
serializable object:

.. code-block:: python

    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        email = TextField()
        password = TextField()
        active = BooleanField(default=True)
        name = db.Column(db.String(80))

        # Custom User Payload
        def get_security_payload(self):
            return {
                'id': self.id,
                'name': self.name,
                'email': self.email
            }

