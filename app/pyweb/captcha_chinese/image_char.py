import base64
import codecs
import os
import random

from PIL import Image, ImageDraw, ImageFont
from io import BytesIO


class RandomChar():
    def Unicode(self):
        val = random.randint(0x4E00, 0x9FBF)
        return unichr(val)

    def GB2312(self):
        head = random.randint(0xB0, 0xCF)
        body = random.randint(0xA, 0xF)
        tail = random.randint(0, 0xF)
        val = (head << 8) | (body << 4) | tail
        str = "%x" % val
        #   return str.decode('hex').decode('gb2312')
        # return str.encode('gb2312').decode('gb2312')
        return codecs.decode(str, 'hex_codec').decode('gb2312')


class ImageChar():

    def get_fonts(self):
        path = os.path.realpath(__file__)
        path=path[:path.index('image_char')]+'fonts'
        fonts=[]
        for rt, dirs, files in os.walk(path):
            for f in files:
                fonts.append(path+os.sep+f)
        return fonts

    def __init__(self, fontColor=(0, 0, 0),
                 size=(100, 40),
                 # fontPath='C:/Windows/Fonts/wqy.ttc',
                 # fontPath='fonts/'+ fonts[random(0,len(fonts))],
                 bgColor=(255, 255, 255),
                 fontSize=21):
        self.size = size
        fonts=self.get_fonts()
        self.fontPath = fonts[random.randint(0,fonts.__len__()-1)]
        self.bgColor = bgColor
        self.fontSize = fontSize
        self.fontColor = fontColor
        self.font = ImageFont.truetype(self.fontPath, self.fontSize)
        self.image = Image.new('RGB', size, bgColor)

    def rotate(self):
        self.image.rotate(random.randint(0, 30), expand=0)

    def drawText(self, pos, txt, fill):
        draw = ImageDraw.Draw(self.image)
        draw.text(pos, txt, font=self.font, fill=fill)
        del draw

    def randRGB(self):
        return (random.randint(10, 255),
                random.randint(10, 255),
                random.randint(10, 255))

    def fontRGB(self):
        return (random.randint(0, 0),
                random.randint(0, 0),
                random.randint(0, 0))

    def randPoint(self):
        (width, height) = self.size
        return (random.randint(0, width), random.randint(0, height))

    def randLine(self, num):
        draw = ImageDraw.Draw(self.image)
        for i in range(0, num):
            draw.line([self.randPoint(), self.randPoint()], self.randRGB())
        del draw

    def randChinese(self, num):
        chars=[]
        for i in range(0, num):
            char= self.__rand_chinese_(i)
            chars.append(char)
            self.rotate()
        self.randLine(5)
        return {"chars":''.join(chars),"image":str(self.change_image_to_base64(self.image),encoding='utf-8')}

    def __rand_chinese_(self,i):
        gap = 1
        start = 1
        try:
            char = RandomChar().GB2312()
            if char is None or len(char)<=0:
                raise RuntimeError('获取随机中文字符出错')
            x = start + self.fontSize * i + random.randint(0, gap) + gap * i
            self.drawText((x, random.randint(0, 5)), char, self.fontRGB())
            return char
        except:
            return self.__rand_chinese_(i)

    def save(self, path):
        self.image.save(path)

    def change_image_to_base64(self,image):
        buffer = BytesIO()
        image.save(buffer, format="PNG")
        img_str = base64.b64encode(buffer.getvalue())
        return img_str



if __name__ == '__main__':
    ic = ImageChar(fontColor=(0, 0, 0))
    chars_info=ic.randChinese(4)
    ic.save("5.jpeg")