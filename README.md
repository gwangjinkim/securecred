
# Introduction

The aim of this package is to simplify the storing (and retrieving) your credential information (or messages) in encrypted files. This package uses the `pyaes` package - and therefore functions as a wrapper for the `pyaes` package.
AES encryption is one of the most secure encryption algorithms around. (The US government relies on it.)

`pyaes`is a pure python implementation of the AES encryption, which therefore doesn't require any external dependencies (thus truly platform agnostic).

The best - most secure modes are CTR (counter mode) and CBC (cipher block chaining mode).
This package hides some details of the `pyaes` package usage by automating key/counter or key/nonce generation and how to use them, and especially how to write them into files and read them back into variables.

So, one main aim of this package is to maximally simplify the procedure of generating and saving your cryptographic key/counter or key/nonce pair into a key file and your credential information (password and username) into separate files (user file and pass file) in an AES encrypted form. It is recommended to store your key file in a separate place.

# Installation

```
pip install securecred
```


# Usage

## Use AES CTR (counter mode) (recommended)


```
import pathlib
from securecred import AESCTR

# create and ensure existence of base directory
home = pathlib.Path.home()
p = (home / "test")
p.mkdir(parents=True, exist_ok=True) 


# initialize instance
aes = AESCTR()

# save credentials in key, username, password files:
aes.set_key_user_pass(
    p / "_key",
    p / "_user",
    p / "_pass",
)
# enter your username and password
# e.g.:
# Username: user123
# Password: pass123 

# read them in and use them:

co = aes.get_key_user_pass(
    p / "_key",
    p / "_user",
    p / "_pass",
)

# you can access username and password from this credential object (co) by:
co.username  ## user123
co.password  ## pass123



# encrypt and decrypt plaintext messages.

message = "This is my message."
key, counter = aes.generate_random_key()
encrypted =  aes.encrypt(plaintext, key=key, counter=counter)
plaintext == aes.decrypt(encrypted, key=key, counter=counter)



# write encrypted message into a file
message = "This is my message."
aes.write(key_file=p / "message.key", message_file=p / "message.crypt", message=message)

## key saved in C:\Users\kimgw1\test\message.key.
## message saved in C:\Users\kimgw1\test\message.crypt.

# read and decrypt message into a file
aes.read(key_file=p / "message.key", message_file=p / "message.crypt")

## 'This is my message.'
```

## Use AES CBC (cipher block chaining mode) (recommended)

```
import pathlib
from securecred import AESCTR

aes = AESCBC()


# save credentials in key, username, password files:

aes.set_key_user_pass(
    p / "_key",
    p / "_user",
    p / "_pass",
)
# enter your username and password
# e.g.:
# Username: user123
# Password: pass123 

# read them in and use them:

co = aes.get_key_user_pass(
    p / "_key",
    p / "_user",
    p / "_pass",
)

# you can access username and password from this credential object (co) by:
co.username  ## user123
co.password  ## pass123

plaintext == aes.decrypt(aes.encrypt(plaintext, key=key, nonce=nonce), key=key, nonce=nonce)

message = "This is my message."
key, nonce = aes.generate_random_key()
encrypted =  aes.encrypt(plaintext, key=key, nonce=nonce)
plaintext == aes.decrypt(encrypted, key=key, nonce=nonce)


# write encrypted message into a file
message = "This is my message."
aes.write(key_file=p / "message.key", message_file=p / "message.crypt", message=message)

## key saved in ~\test\message.key.
## message saved in ~\test\message.crypt.

# read and decrypt message into a file
aes.read(key_file=p / "message.key", message_file=p / "message.crypt")

## 'This is my message.'

```

## Streamline AES CBC and AES CTR usage by using key_tuple instead of key, nonce/counter

```
import pathlib
from securecred import AESCTR, AESCBC

aes = AESCBC()
# or 
aes = AESCBC()
```

For all procedures which involve writing/reading, anyway the use of nonce or counter is hidden inside.
So the interface looks exactly the same for both:

```
# save credentials in key, username, password files:

aes.set_key_user_pass(
    p / "_key",
    p / "_user",
    p / "_pass",
)
# enter your username and password
# e.g.:
# Username: user123
# Password: pass123 

# read them in and use them:

co = aes.get_key_user_pass(
    p / "_key",
    p / "_user",
    p / "_pass",
)

# you can access username and password from this credential object (co) by:
co.username  ## user123
co.password  ## pass123

# write encrypted message into a file
message = "This is my message."
aes.write(key_file=p / "message.key", message_file=p / "message.crypt", message=message)

## key saved in ~\test\message.key.
## message saved in ~\test\message.crypt.

# read and decrypt message into a file
aes.read(key_file=p / "message.key", message_file=p / "message.crypt")

## 'This is my message.'
```

When encoding and decoding single message manually, you can use `key_tuple` for the
`key` and `nonce`/`counter` pairs like this:

```
message = "This is my message."
key_tuple = aes.generate_random_key()
encrypted =  aes.encrypt(plaintext, *key_tuple)
plaintext == aes.decrypt(encrypted, *key_tuple)
```

Then, the syntax for both classes is exactly the same.


## Use simpler AES CTR (default counter) (less secure)

```
import pathlib
from securecred import AES

# create and ensure existence of base directory
home = pathlib.Path.home()
p = (home / "test")
p.mkdir(parents=True, exist_ok=True) 


# initialize instance
aes = AES()


# save credentials in key, username, password files:

aes.set_key_user_pass(
    p / "_key",
    p / "_user",
    p / "_pass",
)
# enter your username and password
# e.g.:
# Username: user123
# Password: pass123 

# read them in and use them:

co = aes.get_key_user_pass(
    p / "_key",
    p / "_user",
    p / "_pass",
)
# you can access username and password from this credential object (co) by:
co.username  ## user123
co.password  ## pass123


# Encrypt and decrypt a normal plaintext message

plaintext = "This is my text."
key = aes.generate_random_key()

plaintext == aes.decrypt(aes.encrypt(plaintext, key=key), key=key)   ## True


# write encrypted message into a file
message = "This is my message."
aes.write(key_file=p / "message.key", message_file=p / "message.crypt", message=message)

## key saved in ~\test\message.key.
## message saved in ~\test\message.crypt.

# read and decrypt message into a file
aes.read(key_file=p / "message.key", message_file=p / "message.crypt")

## 'This is my message.'

```