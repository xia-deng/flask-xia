from flask.globals import current_app
from flask_login.mixins import UserMixin
from sqlalchemy import Table
from sqlalchemy.ext.declarative.api import declarative_base
from sqlalchemy.sql.schema import ForeignKey
from sqlalchemy.sql.sqltypes import Integer
from werkzeug.security import generate_password_hash, check_password_hash

from app import db, login_manager
from app.pyweb.common.db_common import DBCommon
from app.pyweb.common.log_common import LogCommon
from app.pyweb.common.time_common import Time_Helper


Base = declarative_base()

class User(UserMixin, Base):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(128), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    roles = db.relationship('Role', secondary='user_role')
    confirmed = db.Column(db.Boolean, default=False)
    create_time = db.Column(db.DateTime, default=Time_Helper().get_utc())
    phone_number = db.Column(db.String(20), unique=True, index=True)
    last_login_time = db.Column(db.DateTime)
    last_login_place = db.Column(db.String(128))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=roles['Administrator'][0]).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()

    def __repr__(self):
        return 'email:%s,username:%s,confirmed:%s' % (self.email, self.username, self.confirmed)

    # password hash set
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def save(self, user):
        db.session.add(user)
        db.session.commit()

    def delete(self, **kwargs):
        str_filters = DBCommon.dictToQueryStr(kwargs)
        User.query.filter(str_filters).first().delete()
        db.session.commit()

    def get_user(self, **kwargs):
        str_filters = DBCommon.dictToQueryStr(kwargs)
        try:
            return User.query.filter(str_filters).first()
        except Exception as e:
            LogCommon.print_log_error("get_user:get user failed:%s" % e)
            return None

    def get_users(self, **kwargs):
        str_filters = DBCommon.dictToQueryStr(kwargs)
        try:
            return User.query.filter(str_filters)
        except Exception as e:
            LogCommon.print_log_error("get_users:get users failed:%s" % e)
            return None

    def confirm(self, user):
        user.confirmed = True
        db.session.add(user)
        db.session.commit()
        return True

    def reset_password(self, newPass):
        if newPass is None:
            return False
        self.password = newPass
        db.session.add(self)
        db.session.commit()
        return True

    def change_email(self, new_email):
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        # self.avatar_hash = _hashlib.md5(
        #     self.email.encode('utf-8')).hexdigest()
        db.session.add(self)
        db.session.commit()
        return True

    @login_manager.user_loader
    def load_user(userid):
        return User.query.filter_by(id=userid).first()

    def can(self, permissions):
        return self.user_role is not None and (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)



class Role(Base):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.relationship('Permission', secondary='role_permission')
    users = db.relationship('User', secondary='user_role')

    def getRoles(self):
        return Role.query.all()

    def getRolesByUser(self,userId):
        return Role.query.filter_by(users=userId)

    def save(self,role):
        db.session.add(role)
        db.session.commit()

    def delete(self,roleId):
        role=Role.query.filter_by(id=roleId).first()
        db.session.remove(role)
        db.session.commit()

    def modify(self,role):
        Role.query.filter_by(id=role.id).update(dict(name=role.name,default=role.default,permissions=role.permissions,users=role.users))
        db.session.commit()

class Permission(Base):
    __tablename__ = 'permissions'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    value = db.Column(db.Boolean, nullable=False)
    # permission_category_id = db.Column(db.Integer, db.ForeignKey('permissions_category.id'))
    role_id = db.relationship('Role', secondary='role_permission')

    def getPermissions(self):
        return Permission.query.all()

    def getPermissionsByRole(self, roleId):
        return Permission.query.filter_by(role_id=roleId)

    def save(self, permission):
        db.session.add(permission)
        db.session.commit()

    def delete(self, id: str):
        str_filters = DBCommon.dictToQueryStr(id=id)
        old_permission = Permission.query.filter(str_filters).first()
        try:
            db.session.remove(old_permission)
            db.session.commit()
        except:
            raise RuntimeError("delete permission faield")

    def modify(self, id: str, permission):
        old_permission = Permission.filter_by(id=id).update(dict(name=permission.name, value=permission.value))
        db.session.commit()
        return None


'''多对多关系中的两个表之间的一个关联表'''
user_role_table = Table('user_role', Base.metadata,
                        db.Column('role_id', Integer, ForeignKey('roles.id')),
                        db.Column('user_id', Integer, ForeignKey('users.id'))
                        )
role_permission_table = Table('role_permission', Base.metadata,
                              db.Column('role_id', Integer, ForeignKey('roles.id')),
                              db.Column('permission_id', Integer, ForeignKey('permissions.id'))
                              )
# 权限管理：0000 0000 0000 0000

# class Permission:
#     FOLLOW = 0x01   #关注用户
#     COMMENT = 0x02  #留言
#     WRITE_ARTICLES = 0x04   #发表文章
#     MODERATE_COMMENTS = 0x08    #管理留言
#     ADMINISTER = 0x80   #超级管理员
#
# class AnonymouseUser(AnonymousUserMixin):
#     def can(self,permissions):
#         return False
#
#     def is_administrator(self):
#         return False
# login_manager.anonymous_user=AnonymouseUser
#
roles = {
    # # 普通用户
    # 'User': (Permission.FOLLOW | Permission.COMMENT | Permission.WRITE_ARTICLES, True),
    # # 协管员
    # 'Moderator': (Permission.FOLLOW | Permission.COMMENT | Permission.WRITE_ARTICLES
    #               | Permission.MODERATE_COMMENTS, False),
    # 超级管理员
    'Administrator': (0xff, False)
}
