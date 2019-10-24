from flask_wtf.form import FlaskForm
from flask_wtf.recaptcha.fields import RecaptchaField
from wtforms.fields.core import StringField, BooleanField
from wtforms.fields.simple import PasswordField, SubmitField, HiddenField, TextField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo, ValidationError

from app.constants import EMAIL_DIAPLAY_NAME, PASSWORD_DIAPLAY_NAME, REMEMBER_ME_DIAPLAY_NAME, SUBMIT_LOGIN_DIAPLAY_NAME
from app.pyweb.auth.custom_fields.my_fields import CaptchaField, CaptchaWidget
from app.pyweb.auth.custom_fields.my_validators import Not_equalTo, Captcha_Check, Captcha_equalTo
from app.pyweb.auth.models.models import User


class LoginForm(FlaskForm):
    email = StringField(EMAIL_DIAPLAY_NAME, validators=[DataRequired(), Length(6, 64), Email()])
    password = PasswordField(PASSWORD_DIAPLAY_NAME, validators=[DataRequired(), Length(6, 18)])
    # recaptcha = RecaptchaField()
    captcha = CaptchaField('验证码')
    captcha_input = StringField('', validators=[DataRequired(), Length(4, 4),
                                                Captcha_equalTo('hidden_right_captcha', '验证码错误')])
    hidden_right_captcha = HiddenField()

    remember_me = BooleanField(REMEMBER_ME_DIAPLAY_NAME)

    submit = SubmitField(SUBMIT_LOGIN_DIAPLAY_NAME)


class RegistrationForm(FlaskForm):
    email = StringField('邮箱', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('用户名', validators=[DataRequired(), Length(1, 64),
                                              Regexp('^[A-Za-z][A-Za-z0-9]*$', 0, '用户名只能包含字母和数字')])
    password = PasswordField('密码',
                             validators=[DataRequired(), EqualTo('repassword', message='两次密码必须相同'), Length(8, 16)])
    repassword = PasswordField('确认密码', validators=[DataRequired()])
    captcha = CaptchaField('验证码')
    captcha_input = StringField('', validators=[DataRequired(), Length(4, 4),
                                                Captcha_equalTo('hidden_right_captcha', '验证码错误')])
    hidden_right_captcha = HiddenField()

    submit = SubmitField('注册')

    def validate_email(self, field):
        if User().get_user(email=field.data):
            # User().delete(field.data)
            raise ValidationError('邮箱已注册')

    def validate_username(self, field):
        if User().get_user(username=field.data):
            # User().delete(username=field.data)
            raise ValidationError('用户名已注册')


class ChangePassowrdForm(FlaskForm):
    old_password = PasswordField('旧密码', validators=[DataRequired()])
    password = PasswordField('新密码', validators=[DataRequired(), Not_equalTo('old_password', message='不能和旧密码相同'),
                                                EqualTo('re_password', message='两次输入的新密码必须相同'), Length(8, 16)])
    re_password = PasswordField('确认新密码', validators=[DataRequired(), Length(8, 16)])
    captcha = CaptchaField('验证码')
    captcha_input=StringField('',validators=[DataRequired(),Length(4,4),Captcha_equalTo('hidden_right_captcha','验证码错误')])
    hidden_right_captcha=HiddenField()
    submit = SubmitField('更新')

class PasswordResetRequestForm(FlaskForm):
    email=StringField('Email',validators=[DataRequired(),Length(1,64),Email()])
    captcha = CaptchaField('验证码')
    captcha_input = StringField('', validators=[DataRequired(), Length(4, 4),
                                                Captcha_equalTo('hidden_right_captcha', '验证码错误')])
    hidden_right_captcha = HiddenField()
    submit=SubmitField('发送重置密码邮件')

class PasswordResetForm(FlaskForm):
    email = StringField('邮箱', validators=[DataRequired(), Length(1, 64),
                                             Email()])
    password = PasswordField('新密码', validators=[
        DataRequired(), EqualTo('password2', message='两次输入的密码必须一致')])
    password2 = PasswordField('再输入一次新密码', validators=[DataRequired()])
    captcha = CaptchaField('验证码')
    captcha_input = StringField('', validators=[DataRequired(), Length(4, 4),
                                                Captcha_equalTo('hidden_right_captcha', '验证码错误')])
    hidden_right_captcha = HiddenField()
    submit = SubmitField('重置密码')

    def validate_email(self,field):
        if User().get_user(email=field.data) is None:
            raise ValidationError('请检查你的邮箱！')

class ChangeEmailForm(FlaskForm):
    email = StringField('新邮箱', validators=[DataRequired(), Length(1, 64),
                                                 Email()])
    password = PasswordField('密码', validators=[DataRequired()])
    captcha = CaptchaField('验证码')
    captcha_input = StringField('', validators=[DataRequired(), Length(4, 4),
                                                Captcha_equalTo('hidden_right_captcha', '验证码错误')])
    hidden_right_captcha = HiddenField()
    submit = SubmitField('更新邮箱')

    def validate_email(self, field):
        if User().get_user(email=field.data):
            raise ValidationError('邮箱已经存在.')
