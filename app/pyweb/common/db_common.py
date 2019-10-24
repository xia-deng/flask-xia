class DBCommon():
    @staticmethod
    def dictToQueryStr(kwargs):
        str_filters = ''
        for key, value in kwargs.items():
            str_filters += ' %s = \'%s\' and' % (key, value)
        str_filters = str_filters[:len(str_filters) - 3]

        return str_filters