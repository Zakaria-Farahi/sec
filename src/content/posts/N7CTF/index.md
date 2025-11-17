---
title: N7CTF challenges
published: 2024-10-07
description: Solving N7CTF challenges
image: "./n7ctf.png"
tags: [N7CTF, CTF]
category: CTF
draft: false
---



first of all, i want to say thank you to the organizers and everyone who had a hand in organizing this event. thanks to the ctf developers for their effort, the challenges were fun to play.  
so, let's start with the network challenges.

## Network
### PORT FLOW
the challenge was easy, just run the game and match the protocols with their ports.
![Screenshot from 2024-10-06 12-07-10](https://github.com/user-attachments/assets/d9533b1f-d8c0-4714-98b9-6dc1b2d55442)


| Protocol | Port Number |
|----------|-------------|
| FTP      | 21          |
| SSH      | 22          |
| TFTP     | 69          |
| HTTP     | 80          |
| NetBus   | 12345       |
| SMTP     | 25          |
| IMAP     | 993         |
| HTTPS    | 443         |
| MySQL    | 3306        |
| LDAP     | 389         |
| ncat     | 31337       |
| NTP      | 123         |

### PACKET LAB
for this challenge, you first need to enable port Fa0 on the pc. 
![Screenshot from 2024-10-06 12-34-02](https://github.com/user-attachments/assets/35fc094c-a559-4ba7-a222-ec2bead582db)

change the ip for all servers to dhcp (except, of course, the dhcp server).  
in the dns server, go to the **Services** tab and select **DNS**.  
![Screenshot from 2024-10-06 12-37-09](https://github.com/user-attachments/assets/7401612e-b980-47a7-8c72-d041b31c2e50)


so, 192.168.1.3 is the ip of **CTF_SERVER**, but it doesn't give us anything.  
let's test 192.168.1.8; there is no server with this ip, but there is a strange server named **Server_MESG**. you can change the ip address to 192.168.1.8 and connect via the browser to this link—you will get that.  

or skip all that, go to **Server_MESG Services**, **HTTP**, and click **edit the image.html**. XD

## Binary
### BOMB GAME
it's just a binary to hex problem.

### Key to the Vault
use dogbolt.org and upload the vulnerable file, then look for this code `3N5ET_5UPR3MACY`.  
it's the secret key you should use to get the flag.
![Screenshot from 2024-10-06 12-47-50](https://github.com/user-attachments/assets/e8b3f5a0-c529-411c-b13b-6a9b9c59a454)


![Screenshot from 2024-10-06 12-48-26](https://github.com/user-attachments/assets/1371ef03-8ad0-4618-b09f-c3118fc066e4)

### PWN the Vault
the challenge should not include canary but i think there is a problem
![Screenshot from 2024-10-06 12-50-59](https://github.com/user-attachments/assets/c20df822-c784-4659-a60d-cd4829ab9025)


### EMAIL
![Screenshot from 2024-10-06 18-33-08](https://github.com/user-attachments/assets/749cbaf2-5a64-4d39-9733-509f47925bc6)


### IMAGE STEGANO

using chatgpt, it gave this code to extract it:

```python
from PIL import Image

def extract_lsb(image_path):
    # Open the image file
    img = Image.open(image_path)
    binary_data = ""
    
    # Get image size
    width, height = img.size
    
    # Loop through each pixel
    for y in range(height):
        for x in range(width):
            # Get the pixel value (RGB tuple)
            pixel = img.getpixel((x, y))
            
            # Extract the least significant bit from each RGB channel
            for color in pixel[:3]:  # Assuming RGB image, ignore alpha if exists
                binary_data += bin(color)[-1]  # Append the LSB of the color value
    
    # Split the binary string into chunks of 8 bits (1 byte)
    binary_chars = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    
    # Convert binary strings to characters
    message = ""
    for byte in binary_chars:
        char = chr(int(byte, 2))
        # Stop if we reach a null character (assuming message ends with a null)
        if char == "\x00":
            break
        message += char
    
    return message

# Use the function to extract the hidden message
image_path = "path_to_your_image.png"
hidden_message = extract_lsb(image_path)
print("Extracted message:", hidden_message)
```

### AUDIO STEGANO
same as before:

```python
import wave

def extract_lsb_from_audio(audio_path):
    # Open the audio file
    audio = wave.open(audio_path, mode='rb')
    
    # Read frames and convert to byte array
    frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))
    
    # Extract the LSB from each byte
    extracted_bits = ''.join([str(frame_bytes[i] & 1) for i in range(len(frame_bytes))])
    
    # Split the binary string into chunks of 8 bits (1 byte)
    binary_chars = [extracted_bits[i:i+8] for i in range(0, len(extracted_bits), 8)]
    
    # Convert binary strings to characters
    message = ""
    for byte in binary_chars:
        char = chr(int(byte, 2))
        # Stop if we reach a null character (assuming message ends with a null)
        if char == "\x00":
            break
        message += char
    
    # Close the audio file
    audio.close()
    
    return message

# Use the function to extract the hidden message
audio_path = "path_to_your_audio.wav"
hidden_message = extract_lsb_from_audio(audio_path)
print("Extracted message:", hidden_message)
```


## Forensics
### Fake TP
open the file with wireshark in the line 20 i've seen (text/x-sh) it may be interested to look at it
click follow TCP stream you should see some functions just remove the bash in every function so it will not be executed and it should give u the flag
![Screenshot from 2024-10-07 10-57-38](https://github.com/user-attachments/assets/2121fabf-1ec9-4460-a1a8-2d09bd1c3a2e)

![Screenshot from 2024-10-07 11-00-51](https://github.com/user-attachments/assets/c376d28a-0f83-4219-ba03-45c7e7f71825)

## Cryptography
### Duplicate Deception
i found this in reddit https://www.reddit.com/r/DataHoarder/comments/gokrmx/these_different_2_images_has_the_same_md5_hash/ just upload the two files and u will get the flag


## Web
### Charikat Dajaj
capture the first request with burpsuite change the user-agent to charikat dajaj it will redirect you to login page tab anything send and capture the request, change the user-agent to charikat dajaj again,
copie the request and make file .txt with it
in sqlmap run 

```bash
python3 sqlmap.py -r req.txt --dbms=MySQL --tables -T users
```

it should give u all the tables we can see the table users in database dbtry1
now run

```bash
sqlmap -r req.txt --dbms=MySQL -D dbtry1 -T users --dump
```
you will get the flag

![Screenshot from 2024-10-06 23-14-32](https://github.com/user-attachments/assets/1e0ad5f7-2107-4190-b9d0-12093942199d)


## Misc
### Escape 3okacha

Blacklisted[27] i think


> All challenges in : [GitHub](https://github.com/Zakaria-Farahi/N7CTF_2024)

