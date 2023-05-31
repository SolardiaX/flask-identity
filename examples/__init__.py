# -*- coding: utf-8 -*-

"""
    examples.models
    ~~~~~~~~~~~~~~~~~~~
    Database Models of Simple Example of Flask-Identity

    :copyright: (c) 2019 by DreamEx Works.
    :license: MIT, see LICENSE for more details.
"""

import sys
from pathlib import Path


identity_module_path = str(Path(__file__).parents[2])
sys.path.append(identity_module_path)
sys.path.append(str(Path(__file__)))
