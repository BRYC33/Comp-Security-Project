from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64

# AES block size in bytes
BLOCK_SIZE = 16
# Fixed salt used for key derivation with PBKDF2
SALT = b'my_fixed_salt'
ITERATIONS = 100000

def pad(msg):
    """
    Apply padding to the plaintext message to make it a multiple of BLOCK_SIZE.
    Each padding byte equals the number of padding bytes added.
    """
    pad_len = BLOCK_SIZE - len(msg) % BLOCK_SIZE
    return msg + bytes([pad_len]) * pad_len

def unpad(msg):
    """
    Remove the PKCS#7-style padding from the decrypted plaintext.
    Assumes the last byte indicates the length of padding.
    """
    pad_len = msg[-1]
    return msg[:-pad_len]

def derive_key(password):
    # Derives a secure 256-bit AES key from a shared password using PBKDF2.
    return PBKDF2(password, SALT, dkLen=32, count=ITERATIONS)

def encrypt(key, plaintext):
    """
    Encrypts a plaintext string using AES in CBC mode with a random IV.
    The result is returned as a base64-encoded string that includes the IV + ciphertext.
    """
    iv = get_random_bytes(BLOCK_SIZE) # Generate a new random IV for every message
    cipher = AES.new(key, AES.MODE_CBC, iv) # Create AES cipher using the key and IV
    padded = pad(plaintext.encode()) # Convert plaintext to bytes and apply padding
    ct = cipher.encrypt(padded) # Encrypt the padded plaintext
    return base64.b64encode(iv + ct).decode() # Combine IV and ciphertext, then encode as base64

def decrypt(key, b64cipher):
    """
    Decrypts a base64-encoded string that contains the IV + ciphertext.
    Uses AES in CBC mode and returns the original plaintext string.
    """
    raw = base64.b64decode(b64cipher)  # Decode the base64 input
    iv = raw[:BLOCK_SIZE]  # Extract the first 16 bytes as the IV
    ct = raw[BLOCK_SIZE:]  # The rest is the ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Recreate the AES cipher using the same IV
    pt = unpad(cipher.decrypt(ct))  # Decrypt and remove padding
    return pt.decode()  # Convert bytes back to a string

