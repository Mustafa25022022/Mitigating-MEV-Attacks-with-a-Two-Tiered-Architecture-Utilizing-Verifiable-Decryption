import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from local_eth_utils import generate_ethereum_raw_tx, calculate_evm_calldata_gas

def generate_keys():
    """ Generate RSA and AES keys """
    key_builder = RSA.generate(2048)
    key_executor = RSA.generate(2048)
    KE = get_random_bytes(32)  # AES 256-bit key
    KB = get_random_bytes(32)
    return key_builder, key_executor, KE, KB

def encrypt_transaction(KE, KB, key_builder, key_executor, tx):
    """ Encrypt transaction data with AES and RSA keys and measure time and size """
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
    
    ciphertext_size = len(C_E1) + len(tag) + len(nonce) + len(C_B2) + len(C_E2)
    
    return C_E1, tag, nonce, C_B2, C_E2, h_tx, encryption_time, ciphertext_size

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
    print("===================================================================")
    print("              Benchmark: Base Encryption Latency                   ")
    print("===================================================================\n")
    
    tx = generate_ethereum_raw_tx(0)
    key_builder, key_executor, KE, KB = generate_keys()
    C_E1, tag, nonce, C_B2, C_E2, h_tx, encryption_time, ciphertext_size = encrypt_transaction(KE, KB, key_builder, key_executor, tx)
    verification_passed, decryption_time = decrypt_and_verify(KE, KB, key_builder, C_B2, C_E1, tag, nonce)
    
    # Calculate the raw ciphertext payload bytes
    overhead_bytes = C_E1 + tag + nonce + C_B2 + C_E2
    
    print(f"[*] Transaction encryption and integrity check executed.")
    print(f"[*] Original Tx Size  : {len(tx)} bytes")
    print(f"[*] Ciphertext Size   : {ciphertext_size} bytes")
    print(f"[*] Encryption Time   : {encryption_time*1000:.3f} ms")
    print(f"[*] Decryption Time   : {decryption_time*1000:.3f} ms")
    print(f"[*] Integrity Passed  : {verification_passed}")
    print(f"\n[*] Theoretical Gas Cost Overhead (Calldata): {calculate_evm_calldata_gas(overhead_bytes)} gas")
    print("===================================================================")

if __name__ == "__main__":
    main()
