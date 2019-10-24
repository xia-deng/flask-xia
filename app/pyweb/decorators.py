from flask_login.utils import current_user
from werkzeug.exceptions import abort

from app.pyweb.auth.models.models import Permission


def permission_required(permission):
    def decorator(f):
        # @wraps(f)
        def decorated_function(*args, **kwargs):
            print('----->用户的权限：%s,有当前权限吗：%s,具有权限吗：%s' % (
            current_user.role.permissions, permission, current_user.can(permission)))
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def admin_required(f):
    return permission_required(Permission.ADMINISTER)(f)
