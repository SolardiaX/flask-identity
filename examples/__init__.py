#  Disclaimer & Copyright Notice
#
#   Project: Flask-Identity
#    Author: hchenam
#
#  Copyright (c) 2020 DreamEx Works, All rights reserved.

# -*- coding: utf-8 -*-

import os
import sys
from pathlib import Path
from flask import Flask


identity_module_path = str(Path(__file__).parents[2])
sys.path.append(identity_module_path)
sys.path.append(str(Path(__file__)))

application_path = os.getcwd()

app = Flask(__name__)

if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)

app.config.update(
    SECRET_KEY="2HF_R3JddWTLu0zJ1kSV-w",

    IDENTITY_HASH_SALT='2HF_R3JddWTLu0zJ1kSV_hash$salt_',
    IDENTITY_TOKEN_SALT='2HF_R3JddWTLu0zJ1kSV_token$salt_',
    IDENTITY_UNAUTHORIZED_VIEW='/login',

    PONY={
        'provider': 'sqlite',
        'filename': str(Path(application_path).joinpath('database.db')),
        'create_db': 'True',
    }
)
