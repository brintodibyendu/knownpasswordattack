import hashlib, bcrypt
#Demonstrates the difference between two types of hashing, SHA1 and Bcrypt
password = input("Input the password to hash\n>")
print("\nSHA1:\n")
for i in range(3):
    setpass = bytes(password, 'utf-8')
    hash_object = hashlib.sha1(setpass)
    guess_pw = hash_object.hexdigest()
    print(guess_pw)
print("\nMD5:\n")
for i in range(3):
    setpass = bytes(password, 'utf-8')
    hash_object = hashlib.md5(setpass)
    guess_pw = hash_object.hexdigest()
    print(guess_pw)
print("\nBCRYPT:\n")
for i in range(3):
    hashed = bcrypt.hashpw(setpass, bcrypt.gensalt(10))

d3a9fb075d49be97f6eaec99399d8cfdd38c7361
1f4a9685e37e4f940d07a9f6b43dc83c
1f4a9685e37e4f940d07a9f6b43dc83c

import nmd5
import unittest
import random
from linkedlist import *
from random import randint

ns2=nmd5.new("street")
print(ns2.hexdigest())


topFrame=Frame(root)
topFrame.pack()
bottomFrame=Frame(root)
bottomFrame.pack(side=BOTTOM)
button1= Button(topFrame,text="Button 1",fg="red")
button2= Button(topFrame,text="Button 2",fg="blue")
button3= Button(topFrame,text="Button 3",fg="green")
button4= Button(bottomFrame,text="Button 4",fg="red")
button1.pack(side=LEFT)
button2.pack(side=LEFT)
button3.pack(side=LEFT)
button4.pack()


from urllib.request import urlopen, hashlib
sha1hash = input("Please input the hash to crack.\n>")
LIST_OF_COMMON_PASSWORDS = str(urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(), 'utf-8')
for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
    hashedGuess = hashlib.sha1(bytes(guess, 'utf-8')).hexdigest()
    if hashedGuess == sha1hash:
        print("The password is ", str(guess))
        quit()
    elif hashedGuess != sha1hash:
        print("Password guess ",str(guess)," does not match, trying next...")
print("Password not in database, we'll get them next time.")


d3a9fb075d49be97f6eaec99399d8cfdd38c7361
d3a9fb075d49be97f6eaec99399d8cfdd38c7361
d3a9fb075d49be97f6eaec99399d8cfdd38c7361

7c4a8d09ca3762af61e59520943dc26494f8941b
7c4a8d09ca3762af61e59520943dc26494f8941b
7c4a8d09ca3762af61e59520943dc26494f8941b

40fe3fae8d3697bfeb614886210a821ad0733583
40fe3fae8d3697bfeb614886210a821ad0733583
40fe3fae8d3697bfeb614886210a821ad0733583


import sha1
def randomString(stringLength=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))
import random
import string
password = input("Input the password to hash\n>")
npass=password
print("\nSHA1:\n")
print(npass)
lpassword=npass.join(randomString(5));
hashedGuess = sha1.sha1(bytes(lpassword, 'utf-8'))
print(hashedGuess)
print(npass)
lpassword=npass.join(randomString(5));
hashedGuess = sha1.sha1(bytes(lpassword, 'utf-8'))
print(hashedGuess)

