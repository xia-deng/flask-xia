

class DBCommon():
    def init_db(self, db):
        # os.environ.setdefault("xia_web_inited", "xia_web_inited")
        # db_init = os.environ.get("xia_web_inited")
        # print(db_init)
        # setx
        print('开始初始化数据库....')
        from app.models.common_models import Init
        try:
            init = Init().get_init_info()
            print(init)
            if init is None:
                db.drop_all()
                db.create_all()
                Init().init()
            else:
                print('drop all tables')
                db.drop_all()
                db.create_all()
        except Exception as e:
            db.create_all()
        # flag = input('数据表已存在，确定重新初始化数据库吗?[Y/N]:')
        # if flag.lower() == 'y':
        #     db.drop_all()
        #     db.create_all()
        print('数据库初始化完成')




        # os.environ.pop("xia_web_inited","xia_web_inited")


if __name__ == '__main__':
    DBCommon().init_db()
