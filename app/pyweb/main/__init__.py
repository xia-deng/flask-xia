from flask.blueprints import Blueprint

main = Blueprint('main', __name__)

from app.pyweb.main import views, errors

from app.pyweb.auth.models.models import Permission

@main.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)


