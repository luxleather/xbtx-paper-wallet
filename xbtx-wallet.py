#!/usr/bin/python

import hashlib
import random
import time
import base58
import ecdsa

from PIL import Image, ImageFont, ImageDraw
import qrcode
import textwrap

class Keys:

    def __init__(self):
        self.privkeyhex = ''
        self.privkeywif = ''
        self.pubaddr = ''

    def seed(self):
        t = int(time.time())
        return str(random.getrandbits(3000) - t)

    def privatekey(self, seed=None):
        if (seed == None): seed = self.seed()
        self.privkeyhex = hashlib.sha256(seed.encode())

    def privatekeywif(self):
        prefix = b'\x80' # x80 XBTX WIF prefix '5'

        d = prefix + self.privkeyhex.digest()
        checksum = self.doublehash256(d).digest()[:4]

        self.privkeywif = base58.b58encode(d + checksum).decode('utf-8')


    def hash160(self, v):
        r = hashlib.new('ripemd160')
        r.update(hashlib.sha256(v).digest())
        return r

    def doublehash256(self, v):
        return hashlib.sha256(hashlib.sha256(v).digest())

    def ecdsaSECP256k1(self, digest):
        # SECP256k1 - Bitcoin elliptic curve
        sk = ecdsa.SigningKey.from_string(digest, curve=ecdsa.SECP256k1)
        return sk.get_verifying_key()

    def publicaddress(self):
        prefix_a = b'\x04'
        prefix_b = b'\x3C' # XBTX bytes x3C with start letter 'R'

        digest = self.privkeyhex.digest()

        p = prefix_a + self.ecdsaSECP256k1(digest).to_string()  # 1 + 32 bytes + 32 bytes

        hash160 = self.hash160(p)

        m = prefix_b + hash160.digest()
        checksum = self.doublehash256(m).digest()[:4]

        self.pubaddr = base58.b58encode(m + checksum).decode('utf-8')

    
    def paper(self):
        img = Image.open("xbtx-paper.png")
        draw = ImageDraw.Draw(img, 'RGBA')
        font1 = ImageFont.truetype('arial.ttf', 40)
        font2 = ImageFont.truetype('arial.ttf', 34)
        # Paste XBTX address and WIF on .png image
        # Write Address
        text_addr = textwrap.wrap(self.pubaddr, width=17)
        y_text = 950
        for line in text_addr:
            width, height = font1.getsize(line)
            draw.text((60, y_text), line, (0,0,51), font=font1)
            y_text += height
        # Write WIF
        text_wif = textwrap.wrap(self.privkeywif, width=20)
        yw_text = 1310
        for line_w in text_wif:
            width, height = font2.getsize(line_w)
            draw.text((610, yw_text), line_w, (0,0,51), font=font2)
            yw_text += height
        # Draw QR codes
        # Address QR code
        qr1 = qrcode.QRCode(box_size=8, border=1)
        qr1.add_data(self.pubaddr)
        qr1.make()
        img_qr1 = qr1.make_image()
        img.paste(img_qr1, (152,1165))
        # WIF QR code
        qr2 = qrcode.QRCode(box_size=6, border=1)
        qr2.add_data(self.privkeywif)
        qr2.make()
        img_qr2 = qr2.make_image()
        img.paste(img_qr2, (722,975))
        # Img Save by public address filename
        del draw
        img.save('{}.png'.format(self.pubaddr))
    

    def generate(self, seed=None):
        self.privatekey(seed)
        self.privatekeywif()
        self.publicaddress()
        self.paper()



    def __str__(self):
        return """
██   ██ ██████  ████████ ██   ██ 
 ██ ██  ██   ██    ██     ██ ██  
  ███   ██████     ██      ███   
 ██ ██  ██   ██    ██     ██ ██  
██   ██ ██████     ██    ██   ██

BITCOIN SUBSIDIUM (XBTX) Paper wallet successfully created!
Name of the file is same as public address.
Please check installation folder.
XBTX Public Address: %s
""" % (self.pubaddr)


if __name__ == "__main__":
    wallet = Keys()
    wallet.generate()

    print(wallet)