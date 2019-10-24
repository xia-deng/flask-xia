from app import db
from app.pyweb.common.time_common import Time_Helper


class Crypto_Nonce(db.Model):
    __tablename__ = 'crypto_nonce'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nonce_id = db.Column(db.String(128), unique=True)
    nonce_content = db.Column(db.Text)
    nonce_type_name = db.Column(db.String(128))
    create_time = db.Column(db.BigInteger, default=Time_Helper.get_timestamp())

    def __repr__(self):
        return 'nonce_id:%s,nonce_content:%s,nonce_type_name:%s,create_time:%s' % (
            self.nonce_id, self.nonce_content, self.nonce_type_name, self.create_time)

    def get_content_id(self, nonce_id, exp):
        now = Time_Helper.get_timestamp()
        crypto_nonce = Crypto_Nonce.query.filter_by(nonce_id=nonce_id).first()
        if crypto_nonce is not None and now - crypto_nonce.create_time > exp:
            self.delete(nonce_id)
            return None
        elif crypto_nonce is None:
            return None
        else:
            return crypto_nonce.nonce_content

    def get_content_type_name(self,type_name,exp):
        now = Time_Helper.get_timestamp()
        crypto_nonce = Crypto_Nonce.query.filter_by(nonce_type_name=type_name).first()
        if crypto_nonce is not None and now - crypto_nonce.create_time > exp:
            self.delete(crypto_nonce.nonce_id)
            return None
        elif crypto_nonce is None:
            return None
        else:
            return crypto_nonce.nonce_content

    def is_valid_id(self, nonce_id, exp):
        content = self.get_content_id(nonce_id, exp)
        if content is None:
            return False
        return True

    def delete(self, nonce_id):
        crypto_record=Crypto_Nonce.query.filter_by(nonce_id=nonce_id).first()
        db.session.delete(crypto_record)
        db.session.commit()

    def save(self, nonce_id, nonce_content,nonce_type_name):
        nonce = Crypto_Nonce(nonce_id=nonce_id, nonce_content=nonce_content,nonce_type_name=nonce_type_name)
        db.session.add(nonce)
        db.session.commit()
