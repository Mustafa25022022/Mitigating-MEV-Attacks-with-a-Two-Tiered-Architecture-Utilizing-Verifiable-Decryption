import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from local_eth_utils import generate_ethereum_raw_tx, calculate_evm_calldata_gas

def simulate_security_checks(tx):
    start_time = time.time()  # Start time for the whole process

    # Generate keys for RSA
    key_builder = RSA.generate(2048)
    key_executor = RSA.generate(2048)

    pk_B = key_builder.publickey()
    pk_E = key_executor.publickey()

    # Symmetric key for AES
    KE = get_random_bytes(32)  # AES key size of 256 bits
    KB = get_random_bytes(32)  # Builder's symmetric key for consistency in architecture sizing

    # Transaction data hashes
    h_tx = SHA256.new(tx).digest()

    # Encrypt the transaction using AES
    cipher_aes = AES.new(KE, AES.MODE_EAX)
    nonce = cipher_aes.nonce
    C_E1, tag = cipher_aes.encrypt_and_digest(tx + h_tx)
    
    # Encrypt the symmetric keys using RSA
    cipher_rsa_B = PKCS1_OAEP.new(pk_B)
    C_B2 = cipher_rsa_B.encrypt(KB)

    cipher_rsa_E = PKCS1_OAEP.new(pk_E)
    C_E2 = cipher_rsa_E.encrypt(KE)
    
    ciphertext_size = len(C_E1) + len(tag) + len(nonce) + len(C_B2) + len(C_E2)

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
    return tampering_detected, integrity_check_passed, total_time, tamper_check_time, ciphertext_size

def main():
    print("===================================================================")
    print("              Benchmark: Builder Tampering Detection               ")
    print("===================================================================\n")
    
    tx = generate_ethereum_raw_tx(0)
    
    # We recalculate the actual full payload strictly on the main thread for the output
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP, AES
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import SHA256
    
    pk_B, pk_E = RSA.generate(2048).publickey(), RSA.generate(2048).publickey()
    KE, KB = get_random_bytes(32), get_random_bytes(32)
    h_tx = SHA256.new(tx).digest()
    
    cipher_aes = AES.new(KE, AES.MODE_EAX)
    C_E1, tag = cipher_aes.encrypt_and_digest(tx + h_tx)
    overhead_bytes = C_E1 + tag + cipher_aes.nonce + PKCS1_OAEP.new(pk_B).encrypt(KB) + PKCS1_OAEP.new(pk_E).encrypt(KE)
    
    tampering_detected, integrity_check_passed, total_time, tamper_check_time, ciphertext_size = simulate_security_checks(tx)

    print(f"[*] Tampering detection checked.")
    print(f"[*] Tampering Detected : {tampering_detected}")
    print(f"[*] Integrity Passed   : {integrity_check_passed}")
    print(f"[*] Overall Execution  : {total_time*1000:.3f} ms")
    print(f"[*] Tamper Check Time  : {tamper_check_time*1000:.3f} ms")
    
    print(f"[*] Original Tx Size   : {len(tx)} bytes")
    print(f"[*] Ciphertext Size    : {ciphertext_size} bytes")
    print(f"\n[*] Theoretical Gas Cost Overhead (Calldata): {calculate_evm_calldata_gas(overhead_bytes)} gas")
    print("===================================================================")

if __name__ == "__main__":
    main()

