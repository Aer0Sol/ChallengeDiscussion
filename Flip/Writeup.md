# Premise

We are supposed to retrieve the key for the given encrypion (AES-ECB) through software fault injection. The key is p-random.
We are given main.py, encrypt.c, a dockerfile and encrypt ELF file. We are also given an additional hint from Flip_v2:

```Changing in main() is not allowed```

Server doesn't give any prompt but from main.py it is clear we have to supply our plaintext in hex of 16 bytes, i_str which acts as the index where we do the fault injection and j_str the amount of bit shifts we are able to do.

```py
 # input format: hex(plaintext) i j
    try:
        plaintext_hex, i_str, j_str = input().split()
```

```py
 # update key, plaintext, and inject the fault
    content[OFFSET_KEY:OFFSET_KEY + 16] = key
    content[OFFSET_PLAINTEXT:OFFSET_PLAINTEXT + 16] = pt
    content[i] ^= (1 << j)
```

# Vulnerability

After some research, I landed on DFA (Differential Fault Analysis) on AES which happens either on the 8th or 9th round of AES Encryption. But since we don't have a window to do the fault injection then, I used Brute-Force from the start of main()'s offset to the end of main()'s offset.
This was because the offset of the plaintext and the key had a difference of exactly 16 bits which is 2^4 or a power of 2.

```py
OFFSET_PLAINTEXT = 0x4010
OFFSET_KEY = 0x4020
```

Which means during writing the modified plaintext (ciphertext) into the file before execution, we can force it to write the key.

```c
// To compile:
// git clone https://github.com/kokke/tiny-AES-c
// gcc encrypt.c tiny-AES-c/aes.c
#include "tiny-AES-c/aes.h"
#include <unistd.h>

uint8_t plaintext[16] = {0x20, 0x24};
uint8_t key[16] = {0x20, 0x24};

int main() {
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    AES_ECB_encrypt(&ctx, plaintext);
    write(STDOUT_FILENO, plaintext, 16); // We can modify exactly here in main() so that STDOUT_FILENO writes the key instead of ciphertext
    return 0;
}
```

# Solution

Due to the hint from Flip_v2, I stuck to brute-forcing only main()'s offsets and nothing else in the ELF file.

```py
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
```

I used nc to remotely connect to the server but after attempting Flip_v2, I realised I could've done it locally given the ELF file and could have saved a lot of minutes.
It exactly landed on this offset and shift value:

```4545 4```

after some disassembly in IDA, it was clear that it was writing the key into the file instead of the ciphertext.
So I sent the received key back to the server
and hence the flag:

```TetCTF{fr0m_0n3_b1t_fl1pp3d_t0_full_k3y_r3c0v3ry}```
