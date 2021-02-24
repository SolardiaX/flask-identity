# -*- coding: utf-8 -*-

"""
    identity.datastore
    ~~~~~~~~~~~~~~~~~~~
    The Predefined Datastore of Flask-Identity

    :author: solardiax <solardiax@hotmail.com>
    :copyright: (c) 2020 by DreamEx Works.
    :license: GPL-3.0, see LICENSE for more details.
"""

import uuid

from .utils import config_value


class Store(object):
    def __init__(self, db):
        self.db = db

    def add(self, obj):
        """
        Add a new object to the database.

        | Session-based ODMs would call something like ``db.session.add(obj)``.
        | Object-based ODMs would call something like ``object.save()``.
        """
        raise NotImplementedError

    def commit(self):
        """
        Save all modified session objects to the database.

        Session-based ODMs would call something like ``db.session.commit()``.
        Object-based ODMs would do nothing.
        """
        raise NotImplementedError

    def delete(self, obj):
        """
        Delete object from database.
        """
        raise NotImplementedError

    def find(self, objectclass, **kwargs):
        """
        Retrieve all objects of type ``objectclass``,
        matching the specified filters in ``**kwargs`` -- case sensitive.
        """
        raise NotImplementedError

    def get(self, objectclass, **kwargs):
        """
        Retrieve the first object of type ``objectclass``,
        matching the specified filters in ``**kwargs`` -- case sensitive.
        """
        raise NotImplementedError

    def save(self, obj):
        """
        Save object to database.

        | Session-based ODMs would do nothing.
        | Object-based ODMs would do something like obj.save().
        """
        raise NotImplementedError


def with_pony_session(f):
    from functools import wraps

    @wraps(f)
    def decorator(*args, **kwargs):
        from pony.orm import db_session
        # noinspection PyProtectedMember
        from pony.orm.core import local
        from flask import (
            after_this_request,
            current_app,
            has_app_context,
            has_request_context,
        )
        from flask.signals import appcontext_popped

        register = local.db_context_counter == 0
        if register and (has_app_context() or has_request_context()):
            db_session.__enter__()

        result = f(*args, **kwargs)

        if register:
            if has_request_context():

                @after_this_request
                def pop(request):
                    db_session.__exit__()
                    return request

            elif has_app_context():

                # noinspection PyProtectedMember,PyUnusedLocal,PyShadowingNames
                @appcontext_popped.connect_via(current_app._get_current_object())
                def pop(sender, *args, **kwargs):
                    while local.db_context_counter:
                        db_session.__exit__()

            else:
                raise RuntimeError("Needs app or request context")
        return result

    return decorator


class PonyStore(Store):
    """
    Implements the DbAdapter interface to find, add, update and delete
    database objects using PonyORM.
    """

    @with_pony_session
    def add(self, obj):
        return obj

    def commit(self):
        self.db.commit()

    @with_pony_session
    def delete(self, obj):
        obj.delete()

    @with_pony_session
    def find(self, objectclass, **kwargs):
        return objectclass.select().filter(**kwargs)

    @with_pony_session
    def get(self, objectclass, **kwargs):
        return objectclass.get(**kwargs)

    @with_pony_session
    def save(self, obj):
        return obj


class IdentityStore(object):
    """
    Abstracted user identity store.

    :param user_model: A user model class definition
    :param role_model: A role model class definition

    Be aware that for mutating operations, the user/role will be added to the
    store (by calling self.put(<object>). If the datastore is session based
    (such as for SQLAlchemyDatastore) it is up to caller to actually
    commit the transaction by calling datastore.commit().
    """

    def __init__(self, user_model, role_model):
        self.user_model = user_model
        self.role_model = role_model

    def _prepare_role_modify_args(self, user, role):
        if not isinstance(user, self.user_model):
            user = self.find_user(**{config_value('IDENTITY_FIELD'): user})
        if isinstance(role, str):
            role = self.find_role(**{'name': role})
        return user, role

    def _prepare_create_user_args(self, **kwargs):
        kwargs.setdefault("active", True)
        roles = kwargs.get("roles", [])
        for i, role in enumerate(roles):
            rn = role.name if isinstance(role, self.role_model) else role
            # see if the role exists
            roles[i] = self.find_role(rn)
        kwargs["roles"] = roles
        if hasattr(self.user_model, "uniquifier"):
            kwargs.setdefault("uniquifier", uuid.uuid4().hex)
        return kwargs

    def find_user(self, *args, **kwargs):
        """Returns a user matching the provided parameters."""
        raise NotImplementedError

    def find_role(self, *args, **kwargs):
        """Returns a role matching the provided name."""
        raise NotImplementedError

    def add_role_to_user(self, user, role):
        """
        Adds a role to a user.

        :param user: The user to manipulate. Can be an User object or lookup key id with ``'IDENTITY_IDENTITY_FIELD'``
        :param role: The role to add to the user. Can be a Role object or
            string role name
        """
        user, role = self._prepare_role_modify_args(user, role)
        if role not in user.roles:
            user.roles.append(role)
            # noinspection PyUnresolvedReferences
            self.save(user)
            return True

        return False

    def remove_role_from_user(self, user, role):
        """
        Removes a role from a user.

        :param user: The user to manipulate. Can be an User object or lookup key id with ``'IDENTIT_IDENTITY_FIELD'``
        :param role: The role to remove from the user. Can be a Role object or
            string role name
        """
        rv = False
        user, role = self._prepare_role_modify_args(user, role)
        if role in user.roles:
            rv = True
            user.roles.remove(role)
            # noinspection PyUnresolvedReferences
            self.save(user)
        return rv

    def toggle_active(self, user):
        """
        Toggles a user's active status. Always returns True.
        """
        user.active = not user.active
        # noinspection PyUnresolvedReferences
        self.save(user)
        return True

    def deactivate_user(self, user):
        """
        Deactivates a specified user. Returns `True` if a change was made.

        This will immediately disallow access to all endpoints that require
        authentication either via session or tokens.
        The user will not be able to log in again.

        :param user: The user to deactivate
        """
        if user.active:
            user.active = False
            # noinspection PyUnresolvedReferences
            self.save(user)
            return True
        return False

    def activate_user(self, user):
        """
        Activates a specified user. Returns `True` if a change was made.

        :param user: The user to activate
        """
        if not user.active:
            user.active = True
            # noinspection PyUnresolvedReferences
            self.save(user)
            return True

        return

    def set_uniquifier(self, user, uniquifier=None):
        """
        Set user's authentication token uniquifier.
        This will immediately render outstanding auth tokens invalid.

        :param user: User to modify
        :param uniquifier: Unique value - if none then uuid.uuid4().hex is used

        This method is a no-op if the user model doesn't contain the attribute
        ``uniquifier``
        """
        if not hasattr(user, "uniquifier"):
            return
        if not uniquifier:
            uniquifier = uuid.uuid4().hex
        user.uniquifier = uniquifier
        # noinspection PyUnresolvedReferences
        self.save(user)

    def create_role(self, **kwargs):
        """
        Creates and returns a new role from the given parameters.
        Supported params (depending on RoleModel):

        :kwparam name: Role name
        """
        role = self.role_model(**kwargs)
        # noinspection PyUnresolvedReferences
        return self.save(role)

    def create_user(self, **kwargs):
        """
        Creates and returns a new user from the given parameters.

        :kwparam name: required.
        :kwparam password:  Hashed password.
        :kwparam roles: list of roles to be added to user.
            Can be Role objects or strings

        .. danger::
           Be aware that whatever `password` is passed in will
           be stored directly in the DB. Do NOT pass in a plaintext password!
           Best practice is to pass in ``hash_password(plaintext_password)``.

        The new user's ``active`` property will be set to true.
        """
        kwargs = self._prepare_create_user_args(**kwargs)
        user = self.user_model(**kwargs)
        # noinspection PyUnresolvedReferences
        return self.save(user)

    def delete_user(self, user):
        """
        Deletes the specified user.

        :param user: The user to delete
        """
        # noinspection PyUnresolvedReferences
        self.delete(user)


class PonyIdentityStore(IdentityStore, PonyStore):
    """
    A Pony ORM identity store implementation of `IdentityStore` for IdentityManager.
    """

    def __init__(self, db, user_model, role_model):
        IdentityStore.__init__(self, user_model, role_model)
        PonyStore.__init__(self, db)

    def find_user(self, *args, **kwargs):
        if len(args) > 0:
            kwargs.update({config_value('IDENTITY_FIELD'): args[0]})

        return self.get(self.user_model, **kwargs)

    def find_role(self, *args, **kwargs):
        if len(args) > 0:
            kwargs.update({config_value('IDENTITY_FIELD'): args[0]})

        return self.get(self.role_model, **kwargs)


class SQLAlchemyStore(Store):
    """
    Implements the DbAdapter interface to find, add, update and delete
    database objects using SQLAlchemy.
    """

    def add(self, obj):
        return self.db.session.add(obj)

    def commit(self):
        self.db.session.commit()

    def delete(self, obj):
        self.db.session.delete(obj)

    def find(self, objectclass, **kwargs):
        query = objectclass.query
        for field_name, field_value in kwargs.items():
            # Make sure that ObjectClass has a 'field_name' property
            field = getattr(objectclass, field_name, None)
            if field is None:
                raise KeyError(
                    "BaseAlchemyAdapter.find_first_object(): Class '%s' has no field '%s'." % (objectclass, field_name)
                )

            # Add a filter to the query
            query = query.filter(field == field_value)

        # Execute query
        return query.all()

    def get(self, objectclass, **kwargs):
        query = objectclass.query
        for field_name, field_value in kwargs.items():
            # Make sure that ObjectClass has a 'field_name' property
            field = getattr(objectclass, field_name, None)
            if field is None:
                raise KeyError(
                    "BaseAlchemyAdapter.find_first_object(): Class '%s' has no field '%s'." % (objectclass, field_name))

            # Add a case sensitive filter to the query
            query = query.filter(field == field_value)  # case sensitive!!

        # Execute query
        return query.first()

    def save(self, obj):
        self.db.session.add(obj)
        self.db.session.commit()
        return obj


class SQLAlchemyIdentityStore(IdentityStore, SQLAlchemyStore):
    """
    A SQLAlchemy identity store implementation of `IdentityStore` for IdentityManager.
    """
    def __init__(self, db, user_model, role_model):
        IdentityStore.__init__(self, user_model, role_model)
        SQLAlchemyStore.__init__(self, db)

    def find_user(self, *args, **kwargs):
        if len(args) > 0:
            kwargs.update({config_value('IDENTITY_FIELD'): args[0]})

        return self.get(self.user_model, **kwargs)

    def find_role(self, *args, **kwargs):
        if len(args) > 0:
            kwargs.update({config_value('IDENTITY_FIELD'): args[0]})

        return self.get(self.role_model, **kwargs)


class MongoEngineStore(Store):
    """
    Implements the DbAdapter interface to find, add, update and delete
    database objects using MongoEngine.
    """
    def add(self, obj):
        return obj.save()

    def commit(self):
        pass

    def delete(self, obj):
        return obj.delete()

    def find(self, objectclass, **kwargs):
        return objectclass.objects(**kwargs).all()

    def get(self, objectclass, **kwargs):
        return objectclass.objects(**kwargs).first()

    def save(self, obj):
        return obj.save()


class MongoEngineIdentityStore(IdentityStore, MongoEngineStore):
    """
    A MongoEngine identity store implementation of `IdentityStore` for IdentityManager.
    """
    def __init__(self, db, user_model, role_model):
        IdentityStore.__init__(self, user_model, role_model)
        MongoEngineStore.__init__(self, db)

    def find_user(self, *args, **kwargs):
        if len(args) > 0:
            kwargs.update({config_value('IDENTITY_FIELD'): args[0]})

        return self.user_model.objects(**kwargs).first()

    def find_role(self, *args, **kwargs):
        if len(args) > 0:
            kwargs.update({config_value('IDENTITY_FIELD'): args[0]})

        return self.role_model.objects(**kwargs).first()
