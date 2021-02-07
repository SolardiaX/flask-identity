#  Disclaimer & Copyright Notice
#
#   Project: Flask-Identity
#    Author: hchenam
#
#  Copyright (c) 2020 DreamEx Works, All rights reserved.

# -*- coding: utf-8 -*-

import sys
from pathlib import Path


identity_module_path = str(Path(__file__).parents[2])
sys.path.append(identity_module_path)
sys.path.append(str(Path(__file__)))
