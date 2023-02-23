import os
import pyaes
import getpass
import copy

class AES:
    """
    AES CTR but with default counter (=1) - thus less secure.
    """

    def __init__(self):
        # 16 bytes = 128 bits, 24 bytes = 192 bits, 32 bytes = 256 bits
        self.key_size = 16

    def generate_random_key(self):
        self.key = os.urandom(self.key_size) # uses system state for better randomization
        return self.key

    def encrypt(self, message, key, counter=100):
        _counter = pyaes.Counter(initial_value=counter)
        aes = pyaes.AESModeOfOperationCTR(key, counter=_counter)
        self.ciphertext = aes.encrypt(message)
        return self.ciphertext

    def decrypt(self, ciphertext, key, counter=100):
        _counter = pyaes.Counter(initial_value=counter)
        aes = pyaes.AESModeOfOperationCTR(key, counter=_counter)
        return aes.decrypt(ciphertext).decode('utf-8')

    def write_encrypted(self, file, ciphertext):
        with open(file, 'wb') as f:
            f.write(ciphertext)
        print(f"message saved in {file}.")

    def read_encrypted(self, file):
        with open(file, "rb") as f:
            return f.read(-1)
    
    def write_key(self, file, key):
        with open(file, 'wb') as f:
            f.write(key)
        print(f"key saved in {file}.")
    
    def read_key(self, file):
        with open(file, 'rb') as f:
            self.key = f.read(self.key_size)
        return self.key

    def set_key_user_pass(self, key_file, user_file, pass_file, key=None, username=None, password=None):
        if key is None:
            key = self.generate_random_key()
        if username is None:
            username = getpass.getpass("Username: ")
        if password is None:
            password = getpass.getpass("Password: ")
        self.write_key(key_file, key)
        self.write_encrypted(user_file, self.encrypt(username, key))
        self.write_encrypted(pass_file, self.encrypt(password, key))

    def get_key_user_pass(self, key_file, user_file, pass_file):
        ca = AES()
        ca._key = self.read_key(key_file)
        ca._user_ciphertext = ca.read_encrypted(user_file)
        ca._pass_ciphertext = ca.read_encrypted(pass_file)
        return ca

    def write(self, key_file, message_file, message, key=None):
        if key is None:
            key = self.generate_random_key()
        self.write_key(key_file, key)
        self.write_encrypted(message_file, self.encrypt(message, key))
    
    def read(self, key_file, message_file):
        ca = AES()
        ca._key = self.read_key(key_file)
        encrypted = ca.read_encrypted(message_file)
        return ca.decrypt(encrypted, ca._key)

    @property
    def username(self):
        return self.decrypt(self._user_ciphertext, key=self._key)

    @property
    def password(self):
        return self.decrypt(self._pass_ciphertext, key=self._key)


class AESCTR:
    """
    AES CTR with explicite counter. - Recommended.
    """

    def __init__(self):
        # 16 bytes = 128 bits, 24 bytes = 192 bits, 32 bytes = 256 bits
        self.key_size = 16
        self.counter_size = 16

    def generate_random_key(self):
        self.key = os.urandom(self.key_size) # uses system state for better randomization
        self.counter_bytes = os.urandom(self.key_size) # uses system state for better randomization
        self.counter = self.bytes2counter(self.counter_bytes)
        return self.key, self.counter
    
    def bytes2counter(self, counter_bytes):
        counter_obj = pyaes.Counter(initial_value=0)
        counter_obj._counter = list(counter_bytes)
        return counter_obj
    
    def counter2bytes(self, counter_obj):
        return bytes(counter_obj._counter)

    def encrypt(self, message, key, counter):
        counter = copy.deepcopy(counter)  # necessary because every encryption and decryption changes state of assigned counter
        aes = pyaes.AESModeOfOperationCTR(key, counter=counter)
        self.ciphertext = aes.encrypt(message)
        return self.ciphertext

    def decrypt(self, ciphertext, key, counter):
        counter = copy.deepcopy(counter)
        aes = pyaes.AESModeOfOperationCTR(key, counter=counter)
        return aes.decrypt(ciphertext).decode('utf-8')

    def write_encrypted(self, file, ciphertext):
        with open(file, 'wb') as f:
            f.write(ciphertext)
        print(f"message saved in {file}.")

    def read_encrypted(self, file):
        with open(file, "rb") as f:
            return f.read(-1)
    
    def write_key(self, file, key, counter):
        with open(file, 'wb') as f:
            for x in (key, self.counter2bytes(counter)):
                f.write(x)
        print(f"key saved in {file}.")
    
    def read_key(self, file):
        with open(file, 'rb') as f:
            self.key, self.counter_bytes = [f.read(x) for x in (self.key_size, self.counter_size)]
            self.counter = self.bytes2counter(self.counter_bytes)
        return self.key, self.counter

    def set_key_user_pass(self, key_file, user_file, pass_file, key=None, counter=None, username=None, password=None):
        if key is None and counter is None:
            key, counter = self.generate_random_key()
        if username is None:
            username = getpass.getpass("Username: ")
        if password is None:
            password = getpass.getpass("Password: ")
        self.write_key(key_file, key, counter)
        self.write_encrypted(user_file, self.encrypt(username, key, counter))
        self.write_encrypted(pass_file, self.encrypt(password, key, counter))

    def get_key_user_pass(self, key_file, user_file, pass_file):
        ca = AESCTR()
        ca._key, ca._counter = self.read_key(key_file)
        ca._user_ciphertext = ca.read_encrypted(user_file)
        ca._pass_ciphertext = ca.read_encrypted(pass_file)
        return ca

    def write(self, key_file, message_file, message, key=None, counter=None):
        if key is None and counter is None:
            key, counter = self.generate_random_key()
        self.write_key(key_file, key, counter)
        self.write_encrypted(message_file, self.encrypt(message, key, counter))
    
    def read(self, key_file, message_file):
        ca = AESCTR()
        ca._key, ca._counter = self.read_key(key_file)
        encrypted = ca.read_encrypted(message_file)
        return ca.decrypt(encrypted, ca._key, ca._counter)

    @property
    def username(self):
        return self.decrypt(self._user_ciphertext, key=self._key, counter=self._counter)

    @property
    def password(self):
        return self.decrypt(self._pass_ciphertext, key=self._key, counter=self._counter)




class AESCBC:
    """
    AES CBC which allows for automatic size of message (padding and managment of blocks automated).
    """

    def __init__(self):
        # 16 bytes = 128 bits, 24 bytes = 192 bits, 32 bytes = 256 bits
        self.key_size = 16
        self.nonce_size = 16
        self.block_size = 16

    def generate_random_key(self):
        self.key = os.urandom(self.key_size)     # uses system state for better randomization
        self.nonce = os.urandom(self.nonce_size) # uses system state for better randomization
        return self.key, self.nonce

    def encrypt(self, message, key, nonce):
        encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key, nonce))
        self.ciphertext = encrypter.feed(message)
        self.ciphertext += encrypter.feed()      # flush
        return self.ciphertext

    def decrypt(self, ciphertext, key, nonce):
        decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(key, nonce))
        res = decrypter.feed(ciphertext)
        res += decrypter.feed()
        return res.decode('utf-8')

    def write_encrypted(self, file, ciphertext):
        with open(file, 'wb') as f:
            f.write(ciphertext)
        print(f"message saved in {file}.")

    def read_encrypted(self, file):
        with open(file, "rb") as f:
            return f.read(-1)
    
    def write_key(self, file, key, nonce):
        with open(file, 'wb') as f:
            for x in (key, nonce):
                f.write(x)
        print(f"key saved in {file}.")
    
    def read_key(self, file):
        with open(file, 'rb') as f:
            self.key, self.nonce = [f.read(x) for x in (self.key_size, self.nonce_size)]
        return self.key, self.nonce

    def set_key_user_pass(self, key_file, user_file, pass_file, key=None, nonce=None, username=None, password=None):
        if key is None and nonce is None:
            key, nonce = self.generate_random_key()
        if username is None:
            username = getpass.getpass("Username: ")
        if password is None:
            password = getpass.getpass("Password: ")
        self.write_key(key_file, key, nonce)
        self.write_encrypted(user_file, self.encrypt(username, key, nonce))
        self.write_encrypted(pass_file, self.encrypt(password, key, nonce))

    def get_key_user_pass(self, key_file, user_file, pass_file):
        ca = AESCBC()
        ca._key, ca._nonce = self.read_key(key_file)
        ca._user_ciphertext = ca.read_encrypted(user_file)
        ca._pass_ciphertext = ca.read_encrypted(pass_file)
        return ca
    
    def write(self, key_file, message_file, message, key=None, nonce=None):
        if key is None and nonce is None:
            key, nonce = self.generate_random_key()
        self.write_key(key_file, key, nonce)
        self.write_encrypted(message_file, self.encrypt(message, key, nonce))
    
    def read(self, key_file, message_file):
        ca = AESCBC()
        ca._key, ca._nonce = self.read_key(key_file)
        encrypted = ca.read_encrypted(message_file)
        return ca.decrypt(encrypted, ca._key, ca._nonce)


    @property
    def username(self):
        return self.decrypt(self._user_ciphertext, key=self._key, nonce=self._nonce)

    @property
    def password(self):
        return self.decrypt(self._pass_ciphertext, key=self._key, nonce=self._nonce)

