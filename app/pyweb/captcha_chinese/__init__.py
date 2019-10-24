# -*- coding: utf-8 -*-
"""
Created on Sun Oct  4 15:57:46 2015

@author: keithguofan
"""
from flask.blueprints import Blueprint

captcha = Blueprint('captcha', __name__)

from app.pyweb.captcha_chinese import views

