from pwn import *
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l

OFFSET_MAIN_START = 0x1169
OFFSET_MAIN_END = 0x11ed

l=[]
for i in range(OFFSET_MAIN_START,OFFSET_MAIN_END+1):
    for shift in range(1,8):

        try:
            io=remote('139.162.24.230', 31339)
            print(i, shift)

            pt=('0'*32)
            payload=f'{pt} {i} {shift}'
            io.sendline(payload)

            ct=io.recvline()
            ct=bytes.fromhex(ct[:-1].decode())
            io.sendline((ct).hex())

            k=io.recvline()
            l.append(k)
            if(k):
                print(k.decode()+", "+str(i)+", "+str(shift))
                sys.exit()
                

        except EOFError:
            continue


print(l)  



