import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import pandas as pd

def generate_keys():
    """ Generate RSA and AES keys """
    key_builder = RSA.generate(2048)
    key_executor = RSA.generate(2048)
    KE = get_random_bytes(32)  # AES 256-bit key
    KB = get_random_bytes(32)
    return key_builder, key_executor, KE, KB

def encrypt_transaction(KE, KB, key_builder, key_executor, tx):
    """ Encrypt transaction data with AES and RSA keys and measure time """
    start_time = time.time()
    cipher_aes = AES.new(KE, AES.MODE_EAX)
    nonce = cipher_aes.nonce
    h_tx = SHA256.new(tx).digest()
    C_E1, tag = cipher_aes.encrypt_and_digest(tx + h_tx)

    cipher_rsa_B = PKCS1_OAEP.new(key_builder.publickey())
    C_B2 = cipher_rsa_B.encrypt(KB)

    cipher_rsa_E = PKCS1_OAEP.new(key_executor.publickey())
    C_E2 = cipher_rsa_E.encrypt(KE)
    encryption_time = time.time() - start_time
    return C_E1, tag, nonce, C_B2, C_E2, h_tx, encryption_time

def decrypt_and_verify(KE, KB, key_builder, C_B2, C_E1, tag, nonce):
    """ Decrypt data, verify integrity, and measure time """
    start_time = time.time()
    cipher_rsa_B = PKCS1_OAEP.new(key_builder)
    KB_decrypted = cipher_rsa_B.decrypt(C_B2)

    cipher_aes = AES.new(KE, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(C_E1, tag)

    decrypted_tx = decrypted_data[:-32]
    decrypted_h_tx = decrypted_data[-32:]

    verification_passed = decrypted_h_tx == SHA256.new(decrypted_tx).digest()
    decryption_time = time.time() - start_time
    return verification_passed, decryption_time

def main():
    tx = b"Transaction Data"
    results = []
    for _ in range(100):  # Run the encryption and decryption 100 times
        key_builder, key_executor, KE, KB = generate_keys()
        C_E1, tag, nonce, C_B2, C_E2, h_tx, encryption_time = encrypt_transaction(KE, KB, key_builder, key_executor, tx)
        verification_passed, decryption_time = decrypt_and_verify(KE, KB, key_builder, C_B2, C_E1, tag, nonce)
        results.append({
            "Encryption Time (s)": encryption_time,
            "Decryption Time (s)": decryption_time,
            "Verification Passed": verification_passed
        })

    # Convert results to DataFrame for easier analysis
    df = pd.DataFrame(results)
    print(df.describe())  # Summarize the statistics of the data
    df.to_csv("encryption_decryption_stats.csv", index=False)  # Save to CSV for further analysis

if __name__ == "__main__":
    main()
