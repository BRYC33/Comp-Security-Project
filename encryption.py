from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64

BLOCK_SIZE = 16
SALT = b'my_fixed_salt'
ITERATIONS = 100000

def pad(msg):
    pad_len = BLOCK_SIZE - len(msg) % BLOCK_SIZE
    return msg + bytes([pad_len]) * pad_len

def unpad(msg):
    pad_len = msg[-1]
    return msg[:-pad_len]

def derive_key(password):
    return PBKDF2(password, SALT, dkLen=32, count=ITERATIONS)

def encrypt(key, plaintext):
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode())
    ct = cipher.encrypt(padded)
    return base64.b64encode(iv + ct).decode()

def decrypt(key, b64cipher):
    raw = base64.b64decode(b64cipher)
    iv = raw[:BLOCK_SIZE]
    ct = raw[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct))
    return pt.decode()

