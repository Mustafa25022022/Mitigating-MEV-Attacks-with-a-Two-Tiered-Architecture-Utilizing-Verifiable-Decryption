import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from local_eth_utils import generate_ethereum_raw_tx, calculate_evm_calldata_gas

def generate_keys():
    """ Generate RSA keys for builders and executors and measure the time taken. """
    start = time.time()
    key_builder = RSA.generate(2048)
    key_executor = RSA.generate(2048)
    elapsed_time = time.time() - start
    return key_builder, key_executor, elapsed_time

def encrypt_transaction(tx, KE, KB, pk_B, pk_E):
    """ Encrypt transaction and keys, return encrypted data and hashes with execution time and size. """
    start = time.time()
    cipher_aes = AES.new(KE, AES.MODE_EAX)
    nonce = cipher_aes.nonce
    C_E1, tag = cipher_aes.encrypt_and_digest(tx)
    h_C_E1 = SHA256.new(C_E1).digest()

    cipher_rsa_B = PKCS1_OAEP.new(pk_B)
    C_B2 = cipher_rsa_B.encrypt(KB)

    cipher_rsa_E = PKCS1_OAEP.new(pk_E)
    C_E2 = cipher_rsa_E.encrypt(KE)

    ciphertext_size = len(C_E1) + len(tag) + len(nonce) + len(C_B2) + len(C_E2)

    elapsed_time = time.time() - start
    return C_E1, tag, nonce, C_B2, C_E2, h_C_E1, elapsed_time, ciphertext_size

def community_verification(C_E1, h_C_E1, C_E2, h_tx):
    """ Verify integrity and measure the time taken for the verification. """
    start = time.time()
    calculated_h_C_E1 = SHA256.new(C_E1).digest()
    builder_verification = calculated_h_C_E1 == h_C_E1

    calculated_h_tx = SHA256.new(h_tx).digest()
    executor_verification = calculated_h_tx == h_tx

    elapsed_time = time.time() - start
    return builder_verification, executor_verification, elapsed_time

def run_simulation(tx):
    """ Run the entire simulation, collecting data for analysis. """
    key_builder, key_executor, key_gen_time = generate_keys()
    KE = get_random_bytes(32)
    KB = get_random_bytes(32)
    h_tx = SHA256.new(tx).digest()

    C_E1, tag, nonce, C_B2, C_E2, h_C_E1, encryption_time, ciphertext_size = encrypt_transaction(tx, KE, KB, key_builder.publickey(), key_executor.publickey())
    builder_verification, executor_verification, verification_time = community_verification(C_E1, h_C_E1, C_E2, h_tx)

    return {
        "Key Generation Time (s)": key_gen_time,
        "Encryption Time (s)": encryption_time,
        "Verification Time (s)": verification_time,
        "Ciphertext Size (bytes)": ciphertext_size,
        "Builder Verification": builder_verification,
        "Executor Verification": executor_verification
    }

def main():
    print("===================================================================")
    print("              Benchmark: Community Verification Latency            ")
    print("===================================================================\n")
    
    tx = generate_ethereum_raw_tx(0)
    result = run_simulation(tx)
    
    # We recalculate the actual full payload strictly on the main thread for gas reporting
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP, AES
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import SHA256
    
    pk_B, pk_E = RSA.generate(2048).publickey(), RSA.generate(2048).publickey()
    KE, KB = get_random_bytes(32), get_random_bytes(32)
    h_tx = SHA256.new(tx).digest()
    
    cipher_aes = AES.new(KE, AES.MODE_EAX)
    C_E1, tag = cipher_aes.encrypt_and_digest(tx)
    overhead_bytes = C_E1 + tag + cipher_aes.nonce + PKCS1_OAEP.new(pk_B).encrypt(KB) + PKCS1_OAEP.new(pk_E).encrypt(KE)
    
    print(f"[*] Community Verification finished.")
    print(f"[*] Builder Verified   : {result['Builder Verification']}")
    print(f"[*] Executor Verified  : {result['Executor Verification']}")
    print(f"[*] Verification Time  : {result['Verification Time (s)']*1000:.3f} ms")
    print(f"[*] Key Gen Time       : {result['Key Generation Time (s)']*1000:.3f} ms")
    
    print(f"[*] Original Tx Size   : {len(tx)} bytes")
    print(f"[*] Ciphertext Size    : {result['Ciphertext Size (bytes)']} bytes")
    print(f"\n[*] Theoretical Gas Cost Overhead (Calldata): {calculate_evm_calldata_gas(overhead_bytes)} gas")
    print("===================================================================")

if __name__ == "__main__":
    main()
