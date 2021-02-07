# -*- coding: utf-8 -*-

"""
    identity.compats
    ~~~~~~~~~~~~~~~~~~~
    Compatibility modules of Flask-Identity

    :author: solardiax <solardiax@hotmail.com>
    :copyright: (c) 2020 by DreamEx Works.
    :license: GPL-3.0, see LICENSE for more details.
"""

import flask

if "quart." in flask.__name__ or hasattr(flask, "_quart_patched"):  # pragma: no cover
    is_quart = True
else:
    is_quart = False


@property
def best(self):  # pragma: no cover
    options = sorted(
        self.options,
        key=lambda option: (option.value != "*", option.quality, option.value),
        reverse=True,
    )
    return options[0].value


def get_quart_status():
    """
    Tests if we are using Quart Patched Flask or Vanilla Flask.
    :return: boolean value determining if it is quart patched flask or not
    """
    return is_quart
