from app import db
from app.pyweb.common import Time_Helper


class Init(db.Model):
    __tablename__ = 'init'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    create_time = db.Column(db.DateTime, default=Time_Helper().get_utc())

    def __repr__(self):
        return 'create_time:%s' % (self.create_time)

    def get_init_info(self):
        try:
            return Init.query.first()
        except:
            return None

    def init(self):
        init = Init()
        db.session.add(init)
        db.session.commit()
