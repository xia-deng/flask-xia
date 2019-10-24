from flask.blueprints import Blueprint

auth = Blueprint('auth', __name__)

from app.pyweb.auth import views