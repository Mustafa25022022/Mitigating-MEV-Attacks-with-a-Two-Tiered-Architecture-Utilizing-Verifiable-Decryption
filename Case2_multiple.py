import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import pandas as pd

def simulate_security_checks():
    start_time = time.time()  # Start time for the whole process

    # Generate keys for RSA
    key_builder = RSA.generate(2048)
    key_executor = RSA.generate(2048)

    pk_B = key_builder.publickey()
    pk_E = key_executor.publickey()

    # Symmetric key for AES
    KE = get_random_bytes(32)  # AES key size of 256 bits

    # Transaction data
    tx = b"Transaction Data"
    h_tx = SHA256.new(tx).digest()

    # Encrypt the transaction using AES
    cipher_aes = AES.new(KE, AES.MODE_EAX)
    nonce = cipher_aes.nonce
    C_E1, tag = cipher_aes.encrypt_and_digest(tx + h_tx)

    # Simulate tampering with the ciphertext by the builder
    tampered_C_E1 = C_E1[:-1] + ((C_E1[-1] ^ 0x01).to_bytes(1, byteorder='big'))
    tamper_time = time.time()  # Time after tampering
    
    try:
        cipher_aes = AES.new(KE, AES.MODE_EAX, nonce=nonce)
        # Attempt to decrypt and verify using the original tag, should fail
        decrypted_data = cipher_aes.decrypt_and_verify(tampered_C_E1, tag)
        tampering_detected = False
    except ValueError:
        tampering_detected = True

    # Integrity check using hash verification
    h_tampered_C_E1 = SHA256.new(tampered_C_E1).digest()
    integrity_check_passed = h_tampered_C_E1 == SHA256.new(C_E1).digest()

    end_time = time.time()  # End time for the whole process
    total_time = end_time - start_time
    tamper_check_time = tamper_time - start_time
    return tampering_detected, integrity_check_passed, total_time, tamper_check_time

def run_tests(num_tests=10):
    results = []
    for _ in range(num_tests):
        tampering_detected, integrity_check_passed, total_time, tamper_check_time = simulate_security_checks()
        results.append({
            "Tampering Detected": tampering_detected,
            "Integrity Check Passed": integrity_check_passed,
            "Total Time (s)": total_time,
            "Tamper Check Time (s)": tamper_check_time
        })


    df = pd.DataFrame(results)
    print(df.describe())  # Show summary statistics for collected data
    return df

if __name__ == "__main__":
    df = run_tests(100)  # Change the number of tests as needed
    df.to_csv("encryption_analysis_results.csv", index=False)  # Save the results for further analysis
