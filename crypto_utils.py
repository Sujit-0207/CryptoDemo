import os
import math
import secrets
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from sympy import mod_inverse

# --- Diffie-Hellman ---
def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters

def generate_dh_keypair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def dh_derive_shared_secret(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    # Derive a 32-byte key for AES
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(shared_key)
    return digest.finalize()

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv, ciphertext

def aes_decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode(errors='ignore')

# --- HMAC ---
def generate_hmac_key():
    return secrets.token_bytes(32)

def compute_hmac(key, message):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message.encode())
    return h.finalize()

def verify_hmac(key, message, tag):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message.encode())
    try:
        h.verify(tag)
        return True
    except Exception:
        return False

# --- ElGamal Digital Signature ---
def elgamal_generate_keypair(p=None, g=None):
    # Use a safe prime if not provided
    if p is None:
        from sympy import nextprime
        p = nextprime(secrets.randbits(256))
    if g is None:
        g = secrets.randbelow(p-2) + 2
    x = secrets.randbelow(p-2) + 1  # Private key
    y = pow(g, x, p)                # Public key
    return {'p': p, 'g': g, 'x': x, 'y': y}

def elgamal_sign(message, keypair):
    p, g, x = keypair['p'], keypair['g'], keypair['x']
    # Properly hash the message and convert to integer
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message.encode())
    m_bytes = digest.finalize()
    m = int.from_bytes(m_bytes, 'big')
    while True:
        k = secrets.randbelow(p-2) + 1
        if math.gcd(k, p-1) == 1:
            break
    r = pow(g, k, p)
    k_inv = mod_inverse(k, p-1)
    s = (k_inv * (m - x * r)) % (p-1)
    return (r, s)

def elgamal_verify(message, signature, keypair):
    p, g, y = keypair['p'], keypair['g'], keypair['y']
    r, s = signature
    if not (0 < r < p):
        return False
    # Properly hash the message and convert to integer
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message.encode())
    m_bytes = digest.finalize()
    m = int.from_bytes(m_bytes, 'big')
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, m, p)
    return v1 == v2
