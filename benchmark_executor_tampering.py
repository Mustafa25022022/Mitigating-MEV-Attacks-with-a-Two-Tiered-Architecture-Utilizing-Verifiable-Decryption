import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from local_eth_utils import generate_ethereum_raw_tx, calculate_evm_calldata_gas

def generate_keys():
    """ Generate RSA keys for builder and executor. """
    start_time = time.time()
    key_builder = RSA.generate(2048)
    key_executor = RSA.generate(2048)
    elapsed = time.time() - start_time
    return key_builder, key_executor, elapsed

def encrypt_transaction(key_builder, key_executor, tx):
    """ Encrypt a predefined transaction and return the ciphertext and other necessary details along with timing and size. """
    start_time = time.time()
    KE = get_random_bytes(32)  # AES key size of 256 bits
    KB = get_random_bytes(32)
    h_tx = SHA256.new(tx).digest()

    cipher_aes = AES.new(KE, AES.MODE_EAX)
    nonce = cipher_aes.nonce
    C_E1, tag = cipher_aes.encrypt_and_digest(tx + h_tx)
    
    cipher_rsa_B = PKCS1_OAEP.new(key_builder.publickey())
    C_B2 = cipher_rsa_B.encrypt(KB)

    cipher_rsa_E = PKCS1_OAEP.new(key_executor.publickey())
    C_E2 = cipher_rsa_E.encrypt(KE)
    
    ciphertext_size = len(C_E1) + len(tag) + len(nonce) + len(C_B2) + len(C_E2)
    
    elapsed = time.time() - start_time
    return KE, nonce, tag, C_E1, tx, h_tx, elapsed, ciphertext_size

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

def main():
    print("===================================================================")
    print("              Benchmark: Executor Tampering Detection              ")
    print("===================================================================\n")
    
    tx = generate_ethereum_raw_tx(0)
    
    key_builder, key_executor, key_gen_time = generate_keys()
    KE, nonce, tag, C_E1, tx, h_tx, encryption_time, ciphertext_size = encrypt_transaction(key_builder, key_executor, tx)
    tampered_tx, tampered_h_tx, tamper_time = tamper_with_transaction(tx)
    result, message, integrity_time = verify_integrity(KE, nonce, tag, C_E1, tampered_h_tx)
    
    # We recalculate the actual full payload strictly on the main thread for gas reporting
    from Crypto.Cipher import PKCS1_OAEP
    pk_B, pk_E = key_builder.publickey(), key_executor.publickey()
    KB = get_random_bytes(32)
    overhead_bytes = C_E1 + tag + nonce + PKCS1_OAEP.new(pk_B).encrypt(KB) + PKCS1_OAEP.new(pk_E).encrypt(KE)
    
    print(f"[*] Tampering detection checked.")
    print(f"[*] Result Message     : {message}")
    print(f"[*] Integrity Passed   : {result}")
    print(f"[*] Encryption Time    : {encryption_time*1000:.3f} ms")
    print(f"[*] Tamper Action Time : {tamper_time*1000:.3f} ms")
    print(f"[*] Integrity Time     : {integrity_time*1000:.3f} ms")
    
    print(f"[*] Original Tx Size   : {len(tx)} bytes")
    print(f"[*] Ciphertext Size    : {ciphertext_size} bytes")
    print(f"\n[*] Theoretical Gas Cost Overhead (Calldata): {calculate_evm_calldata_gas(overhead_bytes)} gas")
    print("===================================================================")

if __name__ == "__main__":
    main()
