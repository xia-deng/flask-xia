import re

from wtforms.compat import text_type
from wtforms.fields.core import Field, StringField
from wtforms.widgets.core import TextInput, HTMLString

from app.pyweb.captcha_chinese.image_char import ImageChar
from app.pyweb.crypto import Crypto


class CaptchaWidget(TextInput):
    # html="<div class='form-group col-md-6'>  <label for='validateCode'>验证码  <small>  点击图片刷新验证码</small>  </label>  <div class='input-group'>  <img style='border-radius: 2px;  cursor: pointer;  position: absolute;  z-index: 3;  left: 0;  top: 0;'  src='data:image/png;base64'>  <input type='text' class='form-control'  id='validateCode' style='padding-left: 110px;' placeholder='验证码' %s>  </div>  </div>"
    def __init__(self):

        # self.chars_info = ImageChar(size=(100, 32)).randChinese(4)
        self.chars=ImageChar(size=(100, 32)).randChinese(4)
        super(CaptchaWidget, self).__init__()

    def __call__(self, field, **kwargs):
        kwargs.setdefault('id', field.id)
        kwargs.setdefault('type', self.input_type)
        #chars = ImageChar(size=(100, 32)).randChinese(4)
        if 'value' not in kwargs:
            kwargs['value'] = field._value()
        # self.chars_info = ImageChar(size=(100, 32)).randChinese(4)
        width = "style=' width: 100%;'"
        html=[]
        #html.append("<div class='input-group' %s >" % width)
        html.append("<img onclick='refresh($(\"#captcha\"))' id='captcha' src='data:image/png;base64,' />")
        #html.append("<input onblur='check(this)' type='text' class='form-control' style='padding-left: 110px;' placeholder='验证码' %s />" % self.html_params(name=field.name, **kwargs))
        #html.append("<input type='hidden' id='right_captcha' value=\"%s\" name='right_captcha'></div>" % str(Crypto().encrypt({'captcha':self.chars.get('chars')}),encoding='utf-8'))
        return HTMLString(''.join(html))



class CaptchaField(StringField):
    widget = CaptchaWidget()

    def _value(self):
        if self.data is not None:
            return text_type(self.data)
        else:
            #widget = CaptchaWidget()
            return ''

    def process_formdata(self, valuelist):
        if valuelist:
            self.data = valuelist[0]
        else:
            self.data = ''

    # def validate(self, form, extra_validators=tuple()):
    #     pattern = re.compile(u'value.*"')
    #     value_input = pattern.findall(str(form.captcha))[0]
    #     pattern = re.compile(u'\w+')
    #     value_input = pattern.findall(value_input)[1]
    #     if value_input == ''.join(self.widget.chars_info.get('chars')):
    #         return True
    #     else:
    #         print('验证码出错了')
    #         widget = CaptchaWidget()
    #         return ''
