import time
from datetime import datetime

'''时间帮助类'''
class Time_Helper():
    UTC_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
    LOCAL_FORMAT = '%Y-%m-%d %H:%M:%S'

    '''获取指定时间或者当前的Unix时间戳'''
    @staticmethod
    def get_timestamp(dt=None):
        dt=dt.timetuple() if dt is not None else time.localtime(time.time())
        s = time.mktime(dt)
        return int(s)

    '''把时间戳转为基于UTC的datetime对象'''
    def stamp_to_dt(self, stamp):
        value = time.localtime(stamp)
        dt = time.strftime(self.LOCAL_FORMAT, value)
        dt = datetime.strptime(dt, self.LOCAL_FORMAT)
        dt = self.local2utc(dt)
        return dt

    '''UTC时间转为Local时间'''
    def utc2local(self, utc_st):
        '''UTC时间转本地时间（+8: 00）'''
        now_stamp = time.time()
        local_time = datetime.datetime.fromtimestamp(now_stamp)
        utc_time = datetime.datetime.utcfromtimestamp(now_stamp)
        offset = local_time - utc_time
        local_st = utc_st + offset
        return local_st

    '''Local时间转为UTC时间'''
    def local2utc(self, local_st):
        '''本地时间转UTC时间（-8: 00）'''
        time_struct = time.mktime(local_st.timetuple())
        utc_st = datetime.utcfromtimestamp(time_struct)
        return utc_st

    '''获取当前的UTC时间'''
    def get_utc(self):
        return datetime.utcnow()


if __name__ == '__main__':
    time_helper = Time_Helper()
    stamp = time_helper.get_timestamp(datetime.now())
    print(stamp)
    print(time_helper.stamp_to_dt(stamp))
    print(time_helper.get_utc())
