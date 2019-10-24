from flask.globals import current_app

from app.pyweb.auth.enums import Crypto_Type_Name
from app.pyweb.crypto import Crypto
from app.pyweb.email import Email


class AuthSupport():
    def send_unconfirmed_email(self, user):
        content = {}
        content['email'] = user.email
        token = Crypto().encrypt(content, current_app.config['EMAIL_TOKEN_EXPIRATION'], True,
                                 Crypto_Type_Name.AUTH_IN_UNCONFIRM_EMAIL.value + '_' + user.email)
        return Email().send_email(user.email, '用户激活邮件', 'auth/email/confirm', user=user, token=token)

    def send_reset_password_email(self, user, next):
        content = {}
        content['id'] = user.id
        token = Crypto().encrypt(content, current_app.config['EMAIL_TOKEN_EXPIRATION'], True,
                                 Crypto_Type_Name.AUTH_IN_UNCONFIRM_EMAIL.value + '_' + str(user.id))
        return Email().send_email(user.email, '重置密码', 'auth/email/reset_password', user=user, token=token
                                  , next=next)

    def send_email_change_email(self, user, email):
        content = {}
        content['id'] = user.id
        content['email'] = email
        token = Crypto().encrypt(content, current_app.config['EMAIL_TOKEN_EXPIRATION'], True,
                                 Crypto_Type_Name.AUTH_IN_EMAIL_CHANGE_EMAIL.value + '_' + str(user.id))
        return Email().send_email(user.email, '更新Email地址', 'auth/email/change_email', user=user, token=token
                                  , next=next)
