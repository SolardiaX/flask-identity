# -*- coding: utf-8 -*-

"""
    identity.mixins
    ~~~~~~~~~~~~~~~~~~~
    Mixins of Flask-Identity

    :author: solardiax <solardiax@hotmail.com>
    :copyright: (c) 2020 by DreamEx Works.
    :license: GPL-3.0, see LICENSE for more details.
"""


# noinspection PyUnresolvedReferences
class RoleMixin(object):
    """Mixin for `Role` model definitions"""

    __hash__ = object.__hash__

    def __eq__(self, other):
        return super(object).__eq__(other)

    def __ne__(self, other):
        return not self.__eq__(other)


# noinspection PyUnresolvedReferences
class UserMixin(object):
    """
    This class adds required methods to the User data-model.

    Example:
        class User(db.Model, UserMixin):
            ...
    """

    __hash__ = object.__hash__

    @property
    def is_actived(self):
        return True if not hasattr(self, 'active') else self.active

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        try:
            return str(self.id)
        except AttributeError:
            raise NotImplementedError('No `id` attribute - override `get_id`')

    def has_roles(self, *requirements):
        """
        Return True if the user has all of the specified roles. Return False otherwise.

        has_roles() accepts a list of requirements:
            has_roles(requirement1, requirement2, requirement3).

        Each requirement is either a role_name, or a tuple_of_role_names.
            role_name example:   'manager'
            tuple_of_role_names: ('funny', 'witty', 'hilarious')

        A role_name-requirement is accepted when the user has this role.
        A tuple_of_role_names-requirement is accepted when the user has ONE of these roles.

        has_roles() returns true if ALL of the requirements have been accepted.

        For example:
            has_roles('a', ('b', 'c'), d)
        Translates to:
            User has role 'a' AND (role 'b' OR role 'c') AND role 'd'
        """
        roles = getattr(self, 'roles') if hasattr(self, 'roles') else ()
        role_names = [(r.name if isinstance(r, RoleMixin) else r) for r in roles]

        for requirement in requirements:
            if isinstance(requirement, (list, tuple)):
                tuple_of_role_names = requirement
                authorized = False
                for role_name in tuple_of_role_names:
                    if role_name in role_names:
                        # tuple_of_role_names requirement was met: break out of loop
                        authorized = True
                        break
                if not authorized:
                    return False
            else:
                # this is a role_name requirement
                role_name = requirement
                # the user must have this role
                if role_name not in role_names:
                    return False  # role_name requirement failed: return False

        # All requirements have been met: return True
        return True

    def get_auth_token(self):
        """
        Constructs the user's authentication token.

        This data **MUST** be securely signed using the identity token_context
        """
        from .utils import current_identity

        field = current_identity.config_value('IDENTITY_FIELD')
        uniquifier = getattr(self, 'uniquifier') if hasattr(self, 'uniquifier') else None

        # noinspection PyProtectedMember
        return current_identity._token_context.generate_token({
            field: getattr(self, field),
            'uniquifier': uniquifier
        })

    def get_security_payload(self):
        """Serialize user object as response payload."""
        from .utils import current_identity

        field = current_identity.config_value('IDENTITY_FIELD')
        uniquifier = getattr(self, 'uniquifier') if hasattr(self, 'uniquifier') else None

        return {"id": str(self.id), field: getattr(self, field), 'uniquifier': uniquifier}

    def __eq__(self, other):
        """
        Checks the equality of two `UserMixin` objects using `get_id`.
        """
        if isinstance(other, UserMixin):
            return self.get_id() == other.get_id()
        return NotImplemented

    def __ne__(self, other):
        """
        Checks the inequality of two `UserMixin` objects using `get_id`.
        """
        equal = self.__eq__(other)
        if equal is NotImplemented:
            return NotImplemented

        return not equal


class AnonymousUserMixin(object):
    """
    This is the default object for representing an anonymous user.
    """

    @property
    def is_authenticated(self):
        return False

    @property
    def is_actived(self):
        return False

    @property
    def is_anonymous(self):
        return True

    def get_id(self):
        return

    # noinspection PyUnusedLocal,PyMethodMayBeStatic
    def has_roles(self, *role):
        return False
