Flask-Identity
===================

.. image:: https://travis-ci.org/solardiax/flask-identity.svg?branch=master
    :target: https://travis-ci.org/solardiax/flask-identity

.. image:: https://coveralls.io/repos/github/solardiax/flask-identity/badge.svg?branch=master
    :target: https://coveralls.io/github/solardiax/flask-identity?branch=master

.. image:: https://img.shields.io/github/tag/solardiax/flask-identity.svg
    :target: https://github.com/solardiax/flask-identity/releases

.. image:: https://img.shields.io/pypi/dm/flask-identity.svg
    :target: https://pypi.python.org/pypi/flask-identity
    :alt: Downloads

.. image:: https://img.shields.io/github/license/solardiax/flask-identity.svg
    :target: https://github.com/solardiax/flask-identity/blob/master/LICENSE
    :alt: License

.. image:: https://readthedocs.org/projects/flask-identity/badge/?version=latest
    :target: https://flask-identity.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

Quickly add security features to your Flask application.

About Flask-Identity
------------------

Flask-Identity allows you to quickly add common security mechanisms to your
Flask application. They include:

1. Session based authentication
2. Role and Permission management
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
direct using some seccessful open-source libraries codes:

* `Flask-Login <https://flask-login.readthedocs.org/en/latest/>`_
* `Flask-Security <https://flask-security.readthedocs.org/en/latest/>`_

Contributing
++++++++++++
Issues and pull requests are welcome. Other maintainers are also welcome. Unlike
the original Flask-Security - issue pull requests against the *master* branch.
Please consult these `contributing`_ guidelines.

.. _contributing: https://github.com/solardiax/flask-identity/blob/master/CONTRIBUTING.rst

Installing
----------
Install and update using `pip <https://pip.pypa.io/en/stable/quickstart/>`_:

::

    pip install -U Flask-Identity


Resources
---------

- `Documentation <https://flask-identity.readthedocs.io/>`_
- `Releases <https://pypi.org/project/Flask-Identity/>`_
- `Issue Tracker <https://github.com/solardiax/flask-identity/issues>`_
- `Code <https://github.com/solardiax/flask-identity/>`_
