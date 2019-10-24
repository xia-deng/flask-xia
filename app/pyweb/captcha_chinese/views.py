from flask.globals import request
from flask.json import jsonify
from werkzeug.routing import ValidationError

from app.pyweb import captcha_chinese
from app.pyweb.captcha_chinese.Error import CaptchaError
from app.pyweb.captcha_chinese.image_char import ImageChar
from app.pyweb.common.time_common import Time_Helper
from app.pyweb.crypto import Crypto

global_captcha = {}


# 主要是验证，如果验证码在30分钟内重复请求了5次，则返回失败
@captcha_chinese.captcha.route('/init')
def get_captcha():
    from_ip = request.remote_addr
    size=500
    if global_captcha.__contains__(from_ip):
        if len(global_captcha[from_ip]) >= size and global_captcha[from_ip][size-1] - global_captcha[from_ip][0] <= 1800:
            raise ValidationError(CaptchaError().times_many_error())
        elif len(global_captcha[from_ip]) >= size and global_captcha[from_ip][size-1] - global_captcha[from_ip][0] > 1800:
            global_captcha[from_ip].remove(global_captcha[from_ip][0])
        global_captcha[from_ip].append(Time_Helper.get_timestamp())
    else:
        global_captcha[from_ip] = []
        global_captcha[from_ip].append(Time_Helper.get_timestamp())
    print(global_captcha)
    chars_img = ImageChar(size=(100, 32)).randChinese(4)
    chars_img['chars']=str(Crypto().encrypt(chars_img['chars']),encoding='utf-8')
    return jsonify(chars_img)


@captcha_chinese.captcha.route('/check', methods=['POST'])
def check_captcha():
    request_json = request.get_json()
    crypto = Crypto()
    try:
        right_captcha = crypto.decrypt(request_json['right_captcha'])
        return crypto.encrypt({'cpatcha_result': request_json['input'] == right_captcha})
    except:
        return crypto.encrypt({'cpatcha_result': False})
