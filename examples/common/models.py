# -*- coding: utf-8 -*-

"""
    examples
    ~~~~~~~~~~~~~~~~~~~
    Simple Example of Flask-Identity
    
    :copyright: (c) 2019 by DreamEx Works.
    :license: MIT, see LICENSE for more details.
"""

from flask_sqlalchemy import SQLAlchemy

from flask_identity.core import IdentityManager
from flask_identity.mixins import UserMixin, RoleMixin
from flask_babel import Babel

identity = IdentityManager()
db = SQLAlchemy()
babel = Babel()


class BaseModel(db.Model):
    __abstract__ = True

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)


class Roles(BaseModel, RoleMixin):
    __tablename__ = 'sys_roles'

    name = db.Column(db.String(50), unique=True, nullable=False, index=True)
    display = db.Column(db.String(50), unique=True, nullable=False)


class Users(BaseModel, UserMixin):
    __tablename__ = 'sys_users'

    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    display = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(64), nullable=False)
    active = db.Column(db.Boolean, default=True)
    uniquifier = db.Column(db.String(64), unique=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    current_login_at = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(64), nullable=True)
    current_login_ip = db.Column(db.String(64), nullable=True)
    login_count = db.Column(db.Integer, default=0)

    roles = db.relationship("Roles", secondary=lambda: users_roles, backref=db.backref('users'), lazy="dynamic")


users_roles = db.Table(
    'sys_users_roles',
    db.Column('user_id', db.Integer, db.ForeignKey(Users.id), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey(Roles.id), primary_key=True),
)
