# Premise

Challenge asks us to be super-fast and for twenty 8-byte keys and to get the flag, simply perform decryption on the secret_message which is encrypted to receive the flag. Encryption done is DES with some shifts for certain parameters involved. Our secret message is of the form:

```b'TOP_SECRET:' + os.urandom(40)```

# Vulnerability

This challenge's intended way to solve is to use Weak DES keys but I exploited the way in which keys were used in encryption (NKEY).

# Solution
Let's start by analysing whether all 20 keys are used. Turns out, due to the STEP variable, only the first 14 are used and the rest are redundant.

```py
  cnt, STEP, KEYS = 0, 14, []
```


With a bit of analysis, it is clear that HKEY doesn't "directly" take part in the encryption process except for its length serving as a parameter for modifying NKEY which is later on used in the encryption.
Shift() function can be analysed directly using ic(). 
Our biggest problem yet comes from the shuffle() function as it uses a PRNG to shuffle the NKEY.

I initially used ic() from icecream module for seeing what happens inside each updation of NKEY but swapped it with print on the final run. We also note what was in NKEY initially before the shift() for later use in decryption.

![image](https://github.com/Aer0Sol/ChallengeDiscussion/assets/112194832/d3672356-3bfa-4e2a-bb78-d7674bbcafa6)

![image](https://github.com/Aer0Sol/ChallengeDiscussion/assets/112194832/1b8bea4e-160d-4950-b599-547d61eede3d)


It is clear that shift() function takes the 13th and 14th key and produces an alternating pattern which is consistent given the same 13th and 14th key supplied. So we can use this as a constant for performing DES Decryption on the client side.

Using pwntools, we can connect to the server and supply our payload but since we are not sure of the final 7 keys in NKEY due to the shuffle() function, we can import permutations from itertools and run through all possible configurations of NKEY for DES Decryption before the server closes.

```py
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
```


And thus, the flag:

```MAPNA{DES_h4s_A_f3W_5pec1f!c_kEys_7eRm3d_we4K_k3Ys_And_Sem1-wE4k_KeY5!}```
  
