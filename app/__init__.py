from flask.app import Flask
from flask_bootstrap import Bootstrap
from flask_login.login_manager import LoginManager
from flask_mail import Mail
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy

from app.pyweb.common import log_common
from app.pyweb.common.log_common import LogCommon
from config import config

bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.session_protection = 'Strong'
login_manager.login_view = 'auth.login'


def create_app(config_name):
    app = Flask(__name__)
    print(__name__)
    app.config.from_object(config[config_name])
    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    # 初始化db
    db.init_app(app)

    login_manager.init_app(app)
    # 初始化日志配置
    common = LogCommon()
    app = common.init_log(app, 'log')

    # 附加路由和自定义的错误页面
    from app.pyweb.main import main
    app.register_blueprint(main)
    # 定义认证路由
    from app.pyweb.auth import auth
    app.register_blueprint(auth, url_prefix='/auth')
    # 定义Captcha路由
    from app.pyweb.captcha_chinese import captcha
    app.register_blueprint(captcha, url_prefix='/captcha')

    return app
