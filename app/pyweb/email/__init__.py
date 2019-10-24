from threading import Thread

from flask import render_template
from flask.globals import current_app
from flask_mail import Message

from app import mail


class Email():
    def send_async_email(self, app, msg):
        with app.app_context():
            print(mail)
            try:
                mail.send(msg)
            except Exception as e:
                raise EmailError(e)

    def send_email(self, to, subject, template, **kwargs):
        try:
            app = current_app._get_current_object()
            msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + ' ' + subject,
                          sender=app.config['FLASKY_MAIL_SENDER'], recipients=[to])
            msg.body = render_template(template + '.txt', **kwargs)
            msg.html = render_template(template + '.html', **kwargs)
            #thr = Thread(target=self.send_async_email, args=[app, msg])
            #thr.start()
            return mail.send(msg)
        except Exception as e:
            raise EmailError(e)


class EmailError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)
