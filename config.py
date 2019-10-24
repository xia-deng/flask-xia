import os
from uuid import UUID

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = 'xia helper web'
    EMAIL_TOKEN_EXPIRATION=3600
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    FLASKY_MAIL_SUBJECT_PREFIX = '[Simple Web]'
    FLASKY_MAIL_SENDER = 'Admin <xia_jinyatai@163.com>'
    FLASKY_ADMIN = 'xia_jinyatai@163.com'
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    RECAPTCHA_PUBLIC_KEY = '6LeYIbsSAAAAACRPIllxA7wvXjIE411PfdB2gt2J'
    RECAPTCHA_PRIVATE_KEY = '6LeYIbsSAAAAAJezaIq3Ft_hSTo0YtyeFG-JgRtu'
    # RECAPTCHA_PARAMETERS = {'hl': 'zh', 'render': 'explicit'}
    # RECAPTCHA_DATA_ATTRS = {'theme': 'dark'}

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    MAIL_SERVER = 'smtp.163.com'
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    # MAIL_USE_TLS = True  ## 默认就是 false, 加上警示自己
    MAIL_USERNAME = 'xia_jinyatai@163.com'
    MAIL_PASSWORD = 'xiaemail1'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
                              'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
                              'sqlite:///' + os.path.join(basedir, 'data-tests.sqlite')


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'sqlite:///' + os.path.join(basedir, 'data.sqlite')


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
