import uuid
from builtins import Exception

from flask.globals import current_app
from itsdangerous import TimedJSONWebSignatureSerializer

from app.pyweb.crypto.models.crypto_nonce_models import Crypto_Nonce


class Crypto():
    def __init__(self):
        try:
            self.secret_key = current_app.config['SECRET_KEY']
            self.expiration = current_app.config['CRYPTO_EXP']
        except:
            self.secret_key = 'secret_web_xia_jinyatai_key'
            self.expiration = 3600

    def encrypt(self, content: dict, expiration=None, nonce=False, type_name=None):
        expiration = self.expiration if expiration is None or expiration<=0 else expiration
        try:
            s = TimedJSONWebSignatureSerializer(self.secret_key, expiration)
            if nonce:
                crypto_nonce = Crypto_Nonce()
                token_in_db = crypto_nonce.get_content_type_name(type_name, expiration)
                if token_in_db is not None:
                    return token_in_db
                content['nonce_id'] = str(uuid.uuid1())
                token = s.dumps(content)
                crypto_nonce.save(content['nonce_id'], token, type_name)
                return token
            else:
                return s.dumps(content)
        except Exception as e:
            raise CryptoError(e)


    def decrypt(self, token):
        s = TimedJSONWebSignatureSerializer(self.secret_key)
        try:
            content = s.loads(token)
            print("密码解密出来是：%s" % content)
            try:
                if content['nonce_id'] is not None:
                    crypto_nonce = Crypto_Nonce()
                    crypto_nonce.delete(content['nonce_id'])
                    content.pop('nonce_id')
                    return content
            except:
                return content
            return content

        except Exception as e:
            raise CryptoError(e)


class CryptoError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)
