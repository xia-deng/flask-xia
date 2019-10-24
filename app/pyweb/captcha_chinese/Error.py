class CaptchaError(object):
    def times_many_error(self):
        return {'errorCode':'0001','errorMsg':'尝试太多次了，请稍等再试'}