import streamlit as st
import base64
import binascii
from crypto_utils import (
    generate_dh_parameters, generate_dh_keypair, dh_derive_shared_secret, aes_encrypt, aes_decrypt,
    generate_hmac_key, compute_hmac, verify_hmac,
    elgamal_generate_keypair, elgamal_sign, elgamal_verify
)

st.set_page_config(page_title="CryptoDemo", layout="wide")
st.title("🔐 CryptoDemo: Cryptography Techniques Demo")

TABS = ["Diffie–Hellman Key Exchange", "HMAC (SHA-256)", "ElGamal Digital Signature"]
tab1, tab2, tab3 = st.tabs(TABS)

with tab1:
    st.header("Diffie–Hellman Key Exchange")
    st.markdown("""
    **Diffie–Hellman** allows two parties to establish a shared secret over an insecure channel. This secret can then be used for symmetric encryption.
    
    **Steps:**
    1. Each party generates a private/public key pair.
    2. They exchange public keys.
    3. Each computes the shared secret.
    4. The shared secret is used for AES encryption/decryption.
    """)
    if st.button("Generate DH Parameters & Keys"):
        parameters = generate_dh_parameters()
        privA, pubA = generate_dh_keypair(parameters)
        privB, pubB = generate_dh_keypair(parameters)
        st.session_state['dh'] = {
            'parameters': parameters,
            'privA': privA, 'pubA': pubA,
            'privB': privB, 'pubB': pubB
        }
        st.success("Keys generated for Party A and Party B.")
    if 'dh' in st.session_state:
        privA = st.session_state['dh']['privA']
        pubA = st.session_state['dh']['pubA']
        privB = st.session_state['dh']['privB']
        pubB = st.session_state['dh']['pubB']
        st.subheader("Public Keys")
        st.code(f"Party A: {pubA.public_numbers().y}\nParty B: {pubB.public_numbers().y}")
        st.subheader("Shared Secret Derivation")
        sharedA = dh_derive_shared_secret(privA, pubB)
        sharedB = dh_derive_shared_secret(privB, pubA)
        st.code(f"Party A's derived secret: {base64.b16encode(sharedA).decode()}")
        st.code(f"Party B's derived secret: {base64.b16encode(sharedB).decode()}")
        if sharedA == sharedB:
            st.success("Both parties computed the same shared secret!")
        else:
            st.error("Shared secrets do not match!")
        st.subheader("Encrypt/Decrypt a Message with AES")
        msg = st.text_input("Message to encrypt", "Hello, CryptoDemo!")
        if st.button("Encrypt with Shared Secret"):
            iv, ciphertext = aes_encrypt(sharedA, msg)
            st.session_state['aes'] = {'iv': iv, 'ciphertext': ciphertext, 'key': sharedA}
            st.code(f"Ciphertext (base64): {base64.b64encode(ciphertext).decode()}")
        if 'aes' in st.session_state:
            if st.button("Decrypt with Shared Secret"):
                iv = st.session_state['aes']['iv']
                ciphertext = st.session_state['aes']['ciphertext']
                key = st.session_state['aes']['key']
                try:
                    plaintext = aes_decrypt(key, iv, ciphertext)
                    st.success(f"Decrypted message: {plaintext}")
                except Exception as e:
                    st.error(f"Decryption failed: {e}")

with tab2:
    st.header("HMAC (SHA-256)")
    st.markdown("""
    **HMAC** (Hash-based Message Authentication Code) provides message integrity and authentication using a secret key and a hash function (SHA-256 here).
    
    **Steps:**
    1. Generate a random key.
    2. Compute HMAC for a message.
    3. Verify HMAC. Tampering with message or HMAC causes verification to fail.
    """)
    if st.button("Generate HMAC Key"):
        key = generate_hmac_key()
        st.session_state['hmac_key'] = key
        st.success("Random HMAC key generated.")
    if 'hmac_key' in st.session_state:
        key = st.session_state['hmac_key']
        msg = st.text_input("Message for HMAC", "Hello, HMAC!")
        if st.button("Compute HMAC"):
            tag = compute_hmac(key, msg)
            st.session_state['hmac_tag'] = tag
            st.code(f"HMAC (hex): {binascii.hexlify(tag).decode()}")
        if 'hmac_tag' in st.session_state:
            tag = st.session_state['hmac_tag']
            tampered_msg = st.text_input("Tampered message (optional)", value=msg)
            tampered_tag = st.text_input("Tampered HMAC (hex, optional)", value=binascii.hexlify(tag).decode())
            if st.button("Verify HMAC"):
                try:
                    tag_bytes = binascii.unhexlify(tampered_tag)
                except Exception:
                    st.error("Invalid HMAC hex!")
                    tag_bytes = None
                if tag_bytes is not None:
                    valid = verify_hmac(key, tampered_msg, tag_bytes)
                    if valid:
                        st.success("HMAC verification succeeded.")
                    else:
                        st.error("HMAC verification failed! (Message or HMAC was tampered)")

with tab3:
    st.header("ElGamal Digital Signature")
    st.markdown("""
    **ElGamal Digital Signature** is a public-key signature scheme for authenticating messages.
    
    **Steps:**
    1. Generate ElGamal keypair.
    2. Sign a message with the private key.
    3. Verify the signature with the public key.
    """)
    if st.button("Generate ElGamal Keypair"):
        keypair = elgamal_generate_keypair()
        st.session_state['elgamal'] = keypair
        st.success("ElGamal keypair generated.")
    if 'elgamal' in st.session_state:
        keypair = st.session_state['elgamal']
        st.code(f"Public key (p, g, y):\np = {keypair['p']}\ng = {keypair['g']}\ny = {keypair['y']}")
        msg = st.text_input("Message to sign", "Hello, ElGamal!")
        if st.button("Sign Message"):
            signature = elgamal_sign(msg, keypair)
            st.session_state['elgamal_sig'] = signature
            st.code(f"Signature: r = {signature[0]}, s = {signature[1]}")
        if 'elgamal_sig' in st.session_state:
            signature = st.session_state['elgamal_sig']
            tampered_msg = st.text_input("Tampered message for verification (optional)", value=msg)
            if st.button("Verify Signature"):
                valid = elgamal_verify(tampered_msg, signature, keypair)
                if valid:
                    st.success("Signature verification succeeded.")
                else:
                    st.error("Signature verification failed! (Message or signature was tampered)")
