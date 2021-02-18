# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys
from pallets_sphinx_themes import ProjectLink

sys.path.insert(0, os.path.abspath('..'))


# -- Project information -----------------------------------------------------

project = 'Flask-Identity'
copyright = '2020, SolardiaX'
author = 'SolardiaX'


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "pallets_sphinx_themes",
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx_issues",
]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3/", None),
    "werkzeug": ("https://werkzeug.palletsprojects.com/", None),
    "click": ("https://click.palletsprojects.com/", None),
    "jinja": ("https://jinja.palletsprojects.com/", None),
    "itsdangerous": ("https://itsdangerous.palletsprojects.com/", None),
    "sqlalchemy": ("https://docs.sqlalchemy.org/", None),
    "wtforms": ("https://wtforms.readthedocs.io/en/stable/", None),
    "blinker": ("https://pythonhosted.org/blinker/", None),
}

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# The master toctree document.
master_doc = 'index'

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'flask'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
html_theme_options = {"index_sidebar_logo": False}

html_context = {
    "project_links": [
        ProjectLink("PyPI releases", "https://pypi.org/project/Flask-Identity/"),
        ProjectLink("Source Code", "https://github.com/solardiax/flask-identity/"),
        ProjectLink(
            "Issue Tracker", "https://github.com/solardiax/flask-identity/issues/"
        ),
    ]
}

# If true, links to the reST sources are added to the pages.
html_show_sourcelink = False

# -- Theme configuration --
html_css_files = ["custom.css"]

# Custom sidebar templates, maps document names to template names.
html_sidebars = {
    "index": ["project.html", "localtoc.html", "searchbox.html"],
    "**": ["localtoc.html", "relations.html", "searchbox.html"],
}

# -- Autodoc ---
add_module_names = False    # Remove module paths from docs
autodoc_default_flags = ['members', 'undoc-members', 'inherited-members']
autodoc_member_order = 'bysource'
autoclass_content = 'both'   # Show class doc, but not __init__ doc

# -- Options for sphinx-issues ---------------------------------------------
# Github repo
issues_github_path = "solardiax/flask-identity"
