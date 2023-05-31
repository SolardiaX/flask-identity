.. rst-class:: hide-header

Welcome to Flask-Identity!
=============================================

.. image:: _static/logo.png
      :alt: Flask-Identity: add a drop of security to your Flask application.
      :align: left
      :width: 100%
      :target: https://github.com/solardiax/flask-identity

Flask-Identity allows you to quickly add common security mechanisms to your
Flask application. They include:

1. Session based authentication
2. User and role management
3. Password hashing
4. Basic HTTP authentication
5. Token based authentication
6. Login tracking
7. JSON/Ajax Support

Why create Flask-Identity?
--------------------------

Currently there are so many security middleware for Flask, most them depends on many extensions/libraries.
It's easy to start but hard to configure because some options are defined by the dependencies.

Flask-Identity is a lightweight security extension with all-in-one configurations and less third dependencies,
some codes are direct merged from other successful open-source libraries:

* `Flask-Login <https://flask-login.readthedocs.org/en/latest/>`_
* `Flask-Security <https://flask-security.readthedocs.org/en/latest/>`_


Getting Started
---------------

.. toctree::
   :maxdepth: 2

   configuration
   models
   decorators
   quickstart

API
---

.. toctree::
   :maxdepth: 2

   api

Additional Notes
----------------

.. toctree::
   :maxdepth: 2

   contributing
   changelog
   authors
