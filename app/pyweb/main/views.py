from datetime import datetime

from flask import session, render_template, current_app
from flask.globals import request
from flask_login.utils import current_user

from app.pyweb.common.log_common import LogCommon
from app.pyweb.init.init_model import Init
from app.pyweb.main import main


@main.before_app_request
def init_db():
    LogCommon.print_log_info("拦截点:%s,请求地址:%s" % (request.endpoint,request.base_url + request.path))
    Init().before_request_init()

    # print('前置处理器')
    # url=str(request.path)
    # if not url.startswith("/static"):
    #     LogCommon.print_log_info("请求地址:%s" % request.base_url+request.path)
        # print(request.base_url) #请求地址
        # print(request.path)
        # print(request.args)
        # print(request.data)
        # print(request.form)
        # print(request.endpoint)
        # print(request.access_route)
        # print(request.blueprint)
        # print(request.authorization)
        # print(request.method)
        # LogCommon.print_log_info("请求地址：%s,入参")
    #db_common=DBCommon()
    #db_common.init_db(db)



@main.route('/', methods=['GET'])
def index():
    if current_user.is_authenticated:
        try:
            session['models'] = current_user.username
        except Exception as e:
            #current_app.logger.info("can not get username,models not login:%s" % e)
            session['models'] = None
    else:
        session['models'] = None

    return render_template('index.html', user=session['models'],
                           current_time=datetime.utcnow())
