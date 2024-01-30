# Premise

Challenge asks us to be super-fast and asks for twenty 8-byte keys and to get the flag, simply perform decryption on the secret_message which is encrypted to receive the flag. Encryption done is DES with some shifts for certain parameters involved. Our Secret message is of the form:

```b'TOP_SECRET:' + os.urandom(40)```

# Vulnerability

This challenge's intended way to solve is to use Weak DES keys but I exploited the way in which Keys were used in Encryption (NKEY).

# Solution
Let's start by analysing whether all 20 keys are used. Turns out, due to the STEP variable, only the first 14 are used and the rest are redundant.

![image](https://github.com/Aer0Sol/ChallengeDiscussion/assets/112194832/232a7055-fdbb-4dc3-bde7-786431d86153)


With a bit of analysis, it is clear that HKEY doesn't "directly" really take part in the encryption process except for its length serving as a parameter for modifying NKEY which is later on used in the encryption.
Shift() function can be analysed directly using ic() 
Our biggest problem yet comes from the shuffle() function as it uses a PRNG to shuffle the NKEY.

I initially used ic() from icecream module for seeing what happens inside each updation of NKEY but swapped it with print on the final run. We also note what was in NKEY initially before the shift() for later use in Decryption.

![image](https://github.com/Aer0Sol/ChallengeDiscussion/assets/112194832/d3672356-3bfa-4e2a-bb78-d7674bbcafa6)

![image](https://github.com/Aer0Sol/ChallengeDiscussion/assets/112194832/1b8bea4e-160d-4950-b599-547d61eede3d)


It is clear that shift() function takes the 13th and 14th key and produces an alternating pattern which is consistent given the same 13th and 14th key supplied. So we can use this as a constant for performing DES Decryption on the client side.

Using pwntools, we can connect to the server and supply our payload but since we are not sure of the final 7 keys in NKEY due to the shuffle() function, we can import permutations from itertools and run through all possible configuration of NKEY for DES Decryption before the server closes.

![image](https://github.com/Aer0Sol/ChallengeDiscussion/assets/112194832/9678ce7a-2815-42ef-8108-b632532926e9)


And thus, the flag:

```MAPNA{DES_h4s_A_f3W_5pec1f!c_kEys_7eRm3d_we4K_k3Ys_And_Sem1-wE4k_KeY5!}```
  
