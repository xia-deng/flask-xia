from enum import Enum


class Crypto_Type_Name(Enum):
    AUTH_IN_UNCONFIRM_EMAIL='auth.unconfirm.email.token'
    AUTH_IN_RESET_PASSWORD_EMAIL = 'auth.resetpassword.email.token'
    AUTH_IN_EMAIL_CHANGE_EMAIL = 'auth.email.change.email.token'