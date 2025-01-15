import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric import dh, dsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac

# Constants
KEY_SIZE = 32  # AES-256 key size in bytes
IV_SIZE = 16  # AES block size and IV size in bytes
HASH_ALGO = hashes.SHA256()  # Define the hashing algorithm to use (SHA-256)

# Generate Diffie-Hellman (DH) parameters for key exchange
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

def generate_dh_key_pair():
    # Generate a private key using DH key pair
    private_key = parameters.generate_private_key()
    # Derive the corresponding public key
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_key(private_key, peer_public_key):
    # Perform a key exchange to compute the shared secret
    shared_secret = private_key.exchange(peer_public_key)
    # Use HKDF to derive a symmetric AES key from the shared secret
    derived_key = HKDF(
        algorithm=HASH_ALGO,
        length=KEY_SIZE,
        salt=None,
        info=b"file encryption",
        backend=default_backend()
    ).derive(shared_secret)
    return derived_key

def save_public_key(public_key, filename):
    with open(filename, "wb") as key_file:
        # Save a public key to a file.
        key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_public_key(filename):
    with open(filename, "rb") as key_file:
        # Load the public key from file
        return serialization.load_pem_public_key(key_file.read(), backend=default_backend())

def generate_signature_key_pair():
    # Generate a DSA private key for signing
    private_key = dsa.generate_private_key(key_size=2048, backend=default_backend())
    # Derive the corresponding public key
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    # Use the private key to sign the message with SHA-256
    signature = private_key.sign(
        message,
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message, signature):
    # Verify the signature using the public key and SHA-256
    public_key.verify(
        signature,
        message,
        hashes.SHA256()
    )

def encrypt_file(filepath, aes_key, iv):
    # Open the file and read its contents
    with open(filepath, "rb") as f:
        data = f.read()
    # Create an AES cipher in with the given key and IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Encrypt the file contents
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    # Write the IV and encrypted data to a new file
    with open(filepath + ".enc", "wb") as f_enc:
        f_enc.write(iv + encrypted_data)
    return encrypted_data

def decrypt_file(filepath, aes_key):
    # Open the encrypted file and read the IV and encrypted contents
    with open(filepath, "rb") as f:
        iv = f.read(IV_SIZE)  # Extract the IV
        encrypted_data = f.read()  # Extract the remaining encrypted data
    # Create an AES cipher with the same key and IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    # Decrypt the file contents
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    # Write the decrypted data to a new file
    with open(filepath.replace(".enc", ".dec"), "wb") as f_dec:
        f_dec.write(decrypted_data)
    return decrypted_data

# Example Usage
if __name__ == "__main__":
    # Generate Diffie-Hellman keys for two users (key exchange setup)
    private_key_user1, public_key_user1 = generate_dh_key_pair()
    private_key_user2, public_key_user2 = generate_dh_key_pair()
    
    # Generate DSA keys for signing messages
    signing_private_key, signing_public_key = generate_signature_key_pair()
    
    # Derive a shared AES key using Diffie-Hellman key exchange
    aes_key = derive_shared_key(private_key_user1, public_key_user2)

 
    # Create a file and write a confidential message into it
    filepath = "message.txt"
    if not os.path.exists(filepath):
        with open(filepath, "w") as f:
            f.write("This is a confidential message.")
    
    # Encrypt the file using AES encryption
    iv = os.urandom(IV_SIZE)  # Generate a random IV
    encrypted_data = encrypt_file(filepath, aes_key, iv)
    
    # Sign the encrypted data with the private DSA key
    signature = sign_message(signing_private_key, encrypted_data)
    
    # Save the signing public key to a file for later verification
    save_public_key(signing_public_key, "signing_public_key.pem")

    # Save the signature to a file
    with open(filepath + ".signature", "wb") as sig_file:
        sig_file.write(signature)
    
    print("File encrypted and signed successfully.")


    # Decrypt the encrypted file using AES decryption
    decrypted_data = decrypt_file(filepath + ".enc", aes_key)

    # Load the signature from the file
    with open(filepath + ".signature", "rb") as sig_file:
        signature = sig_file.read()

    # Load the signing public key from the file
    public_key = load_public_key("signing_public_key.pem")
    
    try:
        # Verify the signature to ensure data integrity and authenticity
        verify_signature(public_key, encrypted_data, signature)
        print("Signature verified successfully.")
        print("Decrypted data:", decrypted_data.decode())
    except Exception as e:
        print(f"Signature verification failed: {e}")
