import re

from wtforms.validators import ValidationError

from app.pyweb.crypto import Crypto


class Not_equalTo(object):
    def __init__(self, fieldname, message=None):
        self.fieldname = fieldname
        self.message = message

    def __call__(self, form, field):
        try:
            other = form[self.fieldname]
        except KeyError:
            raise ValidationError(field.gettext("Invalid field name '%s'.") % self.fieldname)
        if field.data == other.data:
            d = {
                'other_label': hasattr(other, 'label') and other.label.text or self.fieldname,
                'other_name': self.fieldname
            }
            message = self.message
            if message is None:
                message = field.gettext('Field must not be equal to %(other_name)s.')

            raise ValidationError(message % d)

class Captcha_equalTo(object):
    def __init__(self, fieldname, message=None):
        self.fieldname = fieldname
        self.message = message

    def __call__(self, form, field):
        try:
            other = form[self.fieldname]
        except KeyError:
            raise ValidationError(field.gettext("Invalid field name '%s'.") % self.fieldname)
        print("hidden captcha real data is:%s" % other.data)
        otherData=Crypto().decrypt(other.data)
        print("hidden captcha real data is:%s" % otherData)
        if not field.data ==otherData:
            d = {
                'other_label': hasattr(other, 'label') and other.label.text or self.fieldname,
                'other_name': self.fieldname
            }
            message = self.message
            if message is None:
                message = field.gettext('Field must not be equal to %(other_name)s.')

            raise ValidationError(message % d)


class Captcha_Check(object):
    def __init__(self, message=None):
        self.message = message

    def __call__(self, form, field):
        print("field is:%s,type of field is:%s" % (field,type(field)))
        pattern = re.compile(u'id=\'right_captcha\'.+"')
        value_input = pattern.findall(field.data)
        pattern = re.compile(u'".*"')
        value_input = pattern.findall(str(value_input))[0][1:-1]
        print(value_input)
        try:
            flag = Crypto().decrypt(value_input)
            print("flag is :%s" % flag)
            if not flag == True:
                raise ValidationError(self.message)
        except:
            raise ValidationError(self.message)
            # try:
            #     other = form[self.fieldname]
            # except KeyError:
            #     raise ValidationError(field.gettext("Invalid field name '%s'.") % self.fieldname)
            # if field.data == other.data:
            #     d = {
            #         'other_label': hasattr(other, 'label') and other.label.text or self.fieldname,
            #         'other_name': self.fieldname
            #     }
            #     message = self.message
            #     if message is None:
            #         message = field.gettext('验证码错误')
            #
            #     raise ValidationError(message % d)


not_equal = Not_equalTo
captcha_check = Captcha_Check
