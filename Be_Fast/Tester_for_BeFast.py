from pwn import *
import secrets
from random import *
from binascii import *
from Crypto.Cipher import DES
from signal import *
import sys, os
from icecream import ic
# def keygen():
#     key = secrets.token_hex(8)
#     return key


# single_key = keygen()

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
# '0c8588e8bc894f6e',
# '617dfb8c14687636',
# 'ea8c30d3e2d77bb6',
# '727d064e1725c734',
# '2c4c050c577365db',
# 'a7e9419add0bc3a8',
]
        
# io = remote('3.75.180.117', 37773)
# io.recvuntil(':')

# for key in keys:
#     io.sendline(key)


# io.interactive()
def shift(msg, l):
	assert l < len(msg)
	return msg[l:] + msg[:l]

def pad(text):
	if len(text) % 8 != 0:
		text += (b'\xff' * (8 - len(text) % 8))
	return text

def encrypt(msg, key):
	msg = pad(msg)
	assert len(msg) % 8 == 0
	assert len(key) == 8
	des = DES.new(key, DES.MODE_ECB)
	enc = des.encrypt(msg)
	return enc

STEP=14
cnt=0
KEYS=[]
secret_msg = b'TOP_SECRET: Helloworld'
for i in d:
    try:
        key = unhexlify(i)
        if len(key) == 8 and key not in KEYS:
            KEYS += [key]
            cnt += 1
        else:
            print('Kidding me!? Bye!!')
    except:
        print('Your key is not valid! Bye!!')
    
    if len(KEYS) == STEP:
        print(KEYS)
        HKEY = KEYS[:7]
        
        shuffle(HKEY)
        print('HKEY:',HKEY)
        NKEY = KEYS[-7:]
        shuffle(NKEY)
        ic('diff:', NKEY)
        for h in HKEY: NKEY = [key, shift(key, 1)] + NKEY; 
        print('this is different:',NKEY)
        enc = encrypt(secret_msg, NKEY[0])
        for key in NKEY[1:]:
            enc = encrypt(enc, key)
        print(f'enc = {hexlify(enc)}')