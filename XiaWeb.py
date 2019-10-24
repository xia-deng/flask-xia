import os

from app import create_app
from app.pyweb.common.log_common import LogCommon

app = create_app(os.getenv('FLASK_CONFIG') or 'default')


class Init_ENV():
    def get_env(self):
        env_names = {"d": '开发者模式', 'p': '生产模式', 't': '测试模式'}
        LogCommon.print_log_info('开始初始化XIA_WEB项目....')
        env_input = ''
        env = input('请输入初始化环境：[default,develop] D,[production] P,[test] T:')
        from app import create_app
        if env is None or env.lower() == 'd':
            env_input = 'd'
            app = create_app('default')
        elif env.lower() == 'p':
            env_input = 'p'
            app = create_app('production')
        elif env.lower() == 't':
            env_input = 't'
            app = create_app('testing')
        else:
            env_input = 'd'
            app = create_app('default')

        LogCommon.print_log_info('初始化完成，你选择了:%s' % env_names[env_input])

        return app


if __name__ == '__main__':
    #app = Init_ENV().get_env()
    # flag = input('是否重置数据库？[Y/N]:')
    # if flag.lower() == 'y':
    #     db = SQLAlchemy(app)
    #     db.drop_all()
    app.debug = True
    app.run()
