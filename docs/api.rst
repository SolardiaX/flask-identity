API
===

Core
----
.. autoclass:: flask_identity.IdentityManager
    :members:

.. data:: flask_identity.current_user

   A proxy for the current user.

.. data:: flask_identity.current_identity

    A proxy for the current Flask_Identity instance.

DataStore
---------

.. autoclass:: flask_identity.datastore.IdentityStore
    :members:

.. autoclass:: flask_identity.datastore.PonyIdentityStore

.. autoclass:: flask_identity.datastore.SQLAlchemyIdentityStore

Protecting Views
----------------
.. autofunction:: flask_identity.auth_required

.. autofunction:: flask_identity.login_required

.. autofunction:: flask_identity.roles_required

.. autofunction:: flask_identity.roles_accepted

User Object Helpers
-------------------
.. autoclass:: flask_identity.UserMixin
   :members:

.. autoclass:: flask_identity.RoleMixin
   :members:

.. autoclass:: flask_identity.AnonymousUserMixin
   :members:


Utils
-----
.. autofunction:: flask_identity.login_user

.. autofunction:: flask_identity.logout_user

.. autofunction:: flask_identity.verify_password

.. autofunction:: flask_identity.hash_password

.. autofunction:: flask_identity.url_for_identity

.. _Flask documentation on signals: https://flask.palletsprojects.com/en/1.1.x/signals/
