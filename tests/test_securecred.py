from securecred import __version__
from securecred import AES, AESCBC, AESCTR
import pathlib
import pytest

def test_version():
    assert __version__ == '0.1.0'

def test_encryption_decryption():
    plaintext = "This is a test string for testing encryption and decryption."
    aes = AES()
    key = aes.generate_random_key()
    assert plaintext == aes.decrypt(aes.encrypt(plaintext, key=key), key=key)

# for handling temporary paths use the tmp_path fixture (a temporary directory which will be deleted after test)

def test_set_get_key_user_pass(tmp_dir):
    key_file, user_file, pass_file = tmp_dir / "_key", tmp_dir / "_user", tmp_dir / "_pass"
    aes = AES()
    aes.set_key_user_pass(key_file, user_file, pass_file)
