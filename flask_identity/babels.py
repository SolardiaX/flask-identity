"""
    identity.babel
    ~~~~~~~~~~~~~~~~~~~
    I18N support modules of Flask-Identity

    :author: solardiax <solardiax@hotmail.com>
    :copyright: (c) 2020 by DreamEx Works.
    :license: GPL-3.0, see LICENSE for more details.
"""

from flask_babel import Domain
from babel.support import LazyProxy
from wtforms.i18n import messages_path

from .utils import config_value

_domain_cls = Domain
_dir_keyword = "translation_directories"


def get_i18n_domain(app):
    kwargs = {
        _dir_keyword: cv("I18N_DIRNAME", app=app),
        "domain": cv("I18N_DOMAIN", app=app),
    }
    return Domain(**kwargs)


def have_babel():
    return True


def is_lazy_string(obj):
    """Checks if the given object is a lazy string."""
    return isinstance(obj, LazyProxy)


def make_lazy_string(__func, msg):
    """Creates a lazy string by invoking func with args."""
    return LazyProxy(__func, msg, enable_cache=False)


class Translations:
    """Fixes WTForms translation support and uses wtforms translations."""

    wtforms_domain = Domain(messages_path(), domain="wtforms")

    def gettext(self, string):
        return self.wtforms_domain.gettext(string)

    def ngettext(self, singular, plural, n):
        return self.wtforms_domain.ngettext(singular, plural, n)
