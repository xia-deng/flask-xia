from flask import redirect, render_template, request
from flask.globals import current_app
from flask.helpers import url_for, flash
from flask_login.utils import login_user, login_required, current_user, logout_user

from app.pyweb import auth
from app.pyweb.auth.forms import LoginForm, RegistrationForm, ChangePassowrdForm, PasswordResetRequestForm, \
    PasswordResetForm, ChangeEmailForm
from app.pyweb.auth.support import AuthSupport
from app.pyweb.common.log_common import LogCommon
from app.pyweb.crypto import Crypto


# @auth.auth.before_app_request
from app.pyweb.decorators import permission_required


def before_request():
    LogCommon.print_log_info("拦截点:%s,请求地址:%s" % (request.endpoint, request.base_url))
    print("current_user.is_authenticated:%s" % current_user.is_authenticated)
    if current_user.is_authenticated \
            and not current_user.confirmed \
            and request.endpoint[:5] != 'auth.' \
            and request.endpoint != 'static':
        return redirect(url_for('auth.unconfirmed'))
    flash("没有权限，请注册以后访问")
    return redirect(url_for('main.index'))


@auth.auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User().get_user(email=form.email.data)
        # 如果用户存在并验证通过
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            if not user.confirmed:  # 如果用户未验证
                return redirect(url_for('auth.unconfirmed'))
            return redirect(request.args.get('next') or url_for('main.index'))
        # 用户不存在或验证未通过
        flash("用户名或密码错误")
        return redirect(url_for('auth.login'))
    return render_template('auth/login.html', form=form)

@auth.auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    print(form.captcha)
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        User().save(user)
        try:
            # AuthSupport().send_unconfirmed_email(user)  # 发送验证邮件
            flash("请激活该用户，激活邮件已发送，请查收")
            current_app._login_disabled = True
            login_user(user)  # 登陆用户
            return redirect(url_for('auth.unconfirmed'))
        except Exception as e:
            LogCommon.print_log_error(e)
            flash("激活邮件发送失败")
            return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


@auth.auth.route('/confirm/<token>',methods=['GET'])
def confirm(token):
    content = Crypto().decrypt(token)
    print(content)
    email = content['email']
    user = User().get_user(email=email)
    login_user(user)
    if user is not None and user.confirm(user):
        flash('已经完成了邮箱确认')
        login_user(user)
        return redirect(url_for('main.index'))
    else:
        try:
            logout_user()
        finally:
            flash('邮箱确认错误或已经超过期限')
    return redirect(url_for('main.index'))


@auth.auth.route('/unconfirmed')
@login_required
def unconfirmed():
    print('------------------------------------------------>用户没有完成认证，进入到未认证页面')
    return render_template('auth/unconfirmed.html')


@auth.auth.route('/confirm',methods=['GET'])
@login_required
def resend_confirmation():
    if current_user.confirmed:
        flash('身份已激活，欢迎回来。')
        return redirect(url_for('main.index'))
    AuthSupport().send_unconfirmed_email(current_user)  # 发送验证邮件
    flash('一封新的确认邮件已经发送到你的注册邮件')
    return redirect(url_for('auth.unconfirmed'))


@auth.auth.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePassowrdForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            User().save(user=current_user)
            flash('密码修改完成')
            return redirect(url_for('main.index'))
        else:
            flash('原密码错误')
    return render_template('auth/change_password.html', form=form)


@auth.auth.route('/reset_password', methods=['GET', 'POST'])
def password_reset_request():
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User().get_user(email=form.email.data)
        if user:
            AuthSupport().send_reset_password_email(user, request.args.get('next'))
            flash('重置密码的邮件已经发送到你的注册邮箱')
            return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)


@auth.auth.route('/reset_password/<token>', methods=['GET', 'POST'])
def password_reset(token):
    # if current_user.is_anonymous:
    #     return redirect(url_for('auth.index'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User().get_user(email=form.email.data)
        if user is None:
            flash("用户不存在！")
            return redirect(url_for('auth.reset_password'))
        content = Crypto().decrypt(token)
        print('decrypt result for reset password: %s' % content)
        if not content['id'] == user.id:
            flash("重置密码失败！")
            return redirect(url_for('auth.reset_password'))
        flag = user.reset_password(form.password.data)
        print("change pass result is:%s" % flag)
        if flag:
            flash('密码已更新')
            return redirect(url_for('auth.login'))
        else:
            flash('密码更新失败')
            return redirect(url_for('auth.reset_password'))
    return render_template('auth/reset_password.html', form=form)


@auth.auth.route('/email', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.WRITE_ARTICLES)
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email = form.email.data
            token = current_user.generate_email_change_token(new_email)
            AuthSupport().send_email_change_email(current_user, new_email)
            flash('更新邮箱的邮件已经发送到你的注册邮箱.')
            return redirect(url_for('main.index'))
        else:
            flash('错误的邮箱或密码.')
    return render_template("auth/change_email.html", form=form)


@auth.auth.route('/email/<token>',methods=['GET'])
@login_required
def change_email(token):
    content = Crypto().decrypt(token)
    if not current_user.id == content['id']:
        flash('邮箱修改失败.')
        return redirect(url_for('auth.change_email_request'))
    if current_user.change_email(content['email']):
        flash('你的注册邮箱已经更新.')
    else:
        flash('邮箱修改失败.')
        return redirect(url_for('auth.change_email_request'))
    return redirect(url_for('main.index'))


@auth.auth.route('/logout',methods=['GET'])
@login_required
def logout():
    logout_user()
    flash('退出登陆')
    return redirect(url_for('main.index'))
