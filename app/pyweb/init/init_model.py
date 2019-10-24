from flask.globals import current_app

from app import db
from app.pyweb.auth.models.models import Role
from app.pyweb.common.time_common import Time_Helper


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

    def is_inited(self):
        inited = self.get_init_info();
        if inited is not None:
            return True
        return False

    def un_init(self):
        db.drop_all()

    def init(self):
        if self.is_inited():
            return None
        self.un_init()
        db.create_all()
        init = Init()
        db.session.add(init)
        db.session.commit()
        Role.insert_roles()

    def before_request_init(self):
        current_app.init = False
        if current_app.init == False and self.is_inited():
            current_app.init = True
        if current_app.init == False:
            self.init()
