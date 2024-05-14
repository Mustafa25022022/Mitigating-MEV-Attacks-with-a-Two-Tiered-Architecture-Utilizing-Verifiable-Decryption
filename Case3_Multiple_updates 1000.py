import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import pandas as pd

def generate_keys():
    """ Generate RSA keys for builder and executor. """
    start_time = time.time()
    key_builder = RSA.generate(2048)
    key_executor = RSA.generate(2048)
    elapsed = time.time() - start_time
    return key_builder, key_executor, elapsed

def encrypt_transaction(key_builder, key_executor):
    """ Encrypt a predefined transaction and return the ciphertext and other necessary details along with timing. """
    start_time = time.time()
    KE = get_random_bytes(32)  # AES key size of 256 bits
    tx = b"Original Transaction Data"
    h_tx = SHA256.new(tx).digest()

    cipher_aes = AES.new(KE, AES.MODE_EAX)
    nonce = cipher_aes.nonce
    C_E1, tag = cipher_aes.encrypt_and_digest(tx + h_tx)
    elapsed = time.time() - start_time
    return KE, nonce, tag, C_E1, tx, h_tx, elapsed

def tamper_with_transaction(tx):
    """ Simulate tampering by modifying the transaction data with timing. """
    start_time = time.time()
    tampered_tx = tx + b" extra data"
    tampered_h_tx = SHA256.new(tampered_tx).digest()
    elapsed = time.time() - start_time
    return tampered_tx, tampered_h_tx, elapsed

def verify_integrity(KE, nonce, tag, C_E1, h_tx):
    """ Attempt to decrypt and verify the integrity of the transaction with timing. """
    start_time = time.time()
    try:
        cipher_aes = AES.new(KE, AES.MODE_EAX, nonce=nonce)
        decrypted_data = cipher_aes.decrypt_and_verify(C_E1, tag)
        decrypted_h_tx = decrypted_data[-32:]
        integrity_check_passed = decrypted_h_tx == h_tx
        elapsed = time.time() - start_time
        return integrity_check_passed, "Tampering not detected", elapsed
    except ValueError:
        elapsed = time.time() - start_time
        return False, "Tampering detected - integrity check failed", elapsed

def run_simulation(num_trials):
    results = []
    for _ in range(num_trials):
        key_builder, key_executor, key_gen_time = generate_keys()
        KE, nonce, tag, C_E1, tx, h_tx, encryption_time = encrypt_transaction(key_builder, key_executor)
        tampered_tx, tampered_h_tx, tamper_time = tamper_with_transaction(tx)
        result, message, integrity_time = verify_integrity(KE, nonce, tag, C_E1, tampered_h_tx)
        results.append({
            'Result': result,
            'Message': message,
            'Key Generation Time (s)': key_gen_time,
            'Encryption Time (s)': encryption_time,
            'Tampering Time (s)': tamper_time,
            'Integrity Check Time (s)': integrity_time
        })
    return pd.DataFrame(results)

if __name__ == "__main__":
    trials = 1000  # Specify the number of trials you want to run
    results_df = run_simulation(trials)
    print(results_df.describe())  # Display statistical summary of the results
    results_df.to_csv("encryption_analysis_results1.csv", index=False)  # Save the results for further analysis
