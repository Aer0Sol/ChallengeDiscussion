# Premise

We are supposed to retrieve the key for the given encrypion (AES-ECB) through software fault injection. The key is p-random.
We are given main.py, encrypt.c, a dockerfile and encrypt ELF file. We are also given an additional hint from Flip_v2:

```Changing in main() is not allowed```

Server doesn't give any prompt but from main.py it is clear we have to supply our plaintext in hex of 16 bytes, i_str which acts as the index where we do the fault injection and j_str the amount of bit shifts we are able to do.

![image](https://github.com/Aer0Sol/ChallengeDiscussion/assets/112194832/519767a0-d0ce-43c3-8476-f9eecf58de59)

![image](https://github.com/Aer0Sol/ChallengeDiscussion/assets/112194832/acf5e175-7b0b-43fe-81bf-441c863982c9)


# Vulnerability

After some research, I landed on DFA (Differential Fault Analysis) on AES which happens either on the 8th or 9th round of AES Encryption. But since we don't have a window to do the fault injection then, I used Brute-Force from the start of main()'s offset to the end of main()'s offset.
This was because the offset of the plaintext and the key had a difference of exactly 16 bits which is 2^4 or a power of 2. Which means during writing the modified plaintext (ciphertext) into the file before execution, we can force it to write the key.

# Solution

Due to the hint from Flip_v2, I stuck to brute-forcing only main()'s offsets and nothing else in the ELF file.

![image](https://github.com/Aer0Sol/ChallengeDiscussion/assets/112194832/eb997f2b-7564-4053-bb9b-b4d7f24bf684)

I used nc to remotely connect to the server but after attempting Flip_v2, I realised I could've done it locally given the ELF file and could have saved a lot of minutes.
It exactly landed on this offset and shift value:

```4545 4```

after some disassembly in IDA, it was clear that it was writing the key into the file instead of the ciphertext.
So I sent the received key back to the server
and hence the flag:

```TetCTF{fr0m_0n3_b1t_fl1pp3d_t0_full_k3y_r3c0v3ry}```
