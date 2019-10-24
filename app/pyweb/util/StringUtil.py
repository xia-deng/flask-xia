class StringUtil(object):
    @staticmethod
    def isBank(str:str):
       return (str is not None) and (str is "") and len(str.strip(" "))>0

    @staticmethod
    def isNotBlank(str:str):
        return

if __name__=='__main__':
   print(StringUtil.isBank(" "))