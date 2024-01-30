from random import *
from binascii import *
from Crypto.Cipher import DES
from Crypto.Util.number import *
from pwn import *
from itertools import *

d = [
    '19de4f4127b03561',
'5a2b1a719860bfaa',
'38b1afb21362f9ef',
'a55e7c74eba6cc21',
'e48fa5b893332293',
'0dc8e83b9d5d488d',
'9015879ddc07e54b',
'bc25df198277fba0',
'db6a085b7de014e1',
'8d5ec6e28d332b8a',
'54c7bb7f62b965f6',
'ea23a30bccf5d829',
'd59c48a153397ca7',
'453acdb991295ca3',
]
       


def unpad(text):
    return text.rstrip(b'\xff')

def decrypt(ciphertext, key):
    assert len(ciphertext) % 8 == 0
    assert len(key) == 8
    des = DES.new(key, DES.MODE_ECB)
    decrypted_msg = des.decrypt(ciphertext)
    return unpad(decrypted_msg)



io = remote('3.75.180.117', 37773)
io.recvuntil(':')

for ki in d:
    io.sendline(ki)

io.recvuntil("']\n")
r=io.recvline().decode().removeprefix("+ enc = b'")
r=r[:-2]
r=bytes.fromhex(r)

io.recvline()

enc=r
dd=[b'\xbc%\xdf\x19\x82w\xfb\xa0',
    b'\x8d^\xc6\xe2\x8d3+\x8a',
    b'\xdbj\x08[}\xe0\x14\xe1',
    b'\xea#\xa3\x0b\xcc\xf5\xd8)',
    b'E:\xcd\xb9\x91)\\\xa3',
    b'T\xc7\xbb\x7fb\xb9e\xf6',
    b'\xd5\x9cH\xa1S9|\xa7']

k=(list(permutations(dd,7)))
for i in k:
    NKEY=[b'E:\xcd\xb9\x91)\\\xa3', b':\xcd\xb9\x91)\\\xa3E', b'E:\xcd\xb9\x91)\\\xa3', b':\xcd\xb9\x91)\\\xa3E', b'E:\xcd\xb9\x91)\\\xa3', b':\xcd\xb9\x91)\\\xa3E', b'E:\xcd\xb9\x91)\\\xa3', b':\xcd\xb9\x91)\\\xa3E', b'E:\xcd\xb9\x91)\\\xa3', b':\xcd\xb9\x91)\\\xa3E', b'E:\xcd\xb9\x91)\\\xa3', b':\xcd\xb9\x91)\\\xa3E', b'E:\xcd\xb9\x91)\\\xa3', b':\xcd\xb9\x91)\\\xa3E']
    NKEY.extend(list(i))
    NKEY.reverse()

    if len(enc)%8!=0:
        continue
    s = decrypt(enc, NKEY[0])
    for key in NKEY[1:]:
        if len(s)%8!=0:
            continue
        s = decrypt(s, key)
    if b'TOP_SECRET:' in s:
        print(s)
        break

io.sendline(s.hex())
print(io.recvline())