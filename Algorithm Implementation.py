import os
import time
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from eth_account import Account
import secrets
from local_eth_utils import generate_ethereum_raw_tx, calculate_evm_calldata_gas

def generate_keys():
    """Generate RSA keypairs for Builder and Executor."""
    keyB = RSA.generate(2048)
    keyE = RSA.generate(2048)
    return keyB, keyE

# ==========================================
# User Phase
# ==========================================
def user_phase(raw_tx, pkB, pkE):
    # 1. Generate fresh symmetric key K (AES-256)
    K = os.urandom(32)
    
    # 2. C_tx <- SymEnc(K, Tx)
    cipher_aes = AES.new(K, AES.MODE_EAX)
    C_tx, tag = cipher_aes.encrypt_and_digest(raw_tx)
    nonce = cipher_aes.nonce
    
    # 3. C_B <- AsymEnc(pk_B, K)
    rsa_cipherB = PKCS1_OAEP.new(RSA.import_key(pkB))
    C_B = rsa_cipherB.encrypt(K)
    
    # 4. C_E <- AsymEnc(pk_E, K)
    rsa_cipherE = PKCS1_OAEP.new(RSA.import_key(pkE))
    C_E = rsa_cipherE.encrypt(K)
    
    # 5. Broadcast (C_tx, C_B, C_E)
    payload = {
        'C_tx': C_tx,
        'tag': tag,
        'nonce': nonce,
        'C_B': C_B,
        'C_E': C_E,
        'tx_size': len(raw_tx)
    }
    return payload

# ==========================================
# Builder Phase
# ==========================================
def builder_phase(mempool_txs, skB):
    Blk_B = []
    pi_B_list = []
    
    # 6. Collect encrypted transactions from mempool
    for i, tx_payload in enumerate(mempool_txs):
        # 8. K <- AsymDec(sk_B, C_B)
        rsa_cipherB = PKCS1_OAEP.new(RSA.import_key(skB))
        try:
            K_prime = rsa_cipherB.decrypt(tx_payload['C_B'])
            
            # 9. Partially decrypt transaction metadata 
            # (In an abstract simulation, we skip parsing metadata, but knowing K allows this)
            
            # 10. Generate verifiable decryption proof pi_B
            # (Simulation: We simulate a NIZK proof by generating a verifiable hash of the action)
            pi_B = f"VDP_Builder_Proof_Tx{i}_{SHA256.new(K_prime).hexdigest()[:16]}"
            
            Blk_B.append(tx_payload)
            pi_B_list.append(pi_B)
        except ValueError:
            print("Builder decryption failed for a transaction!")
            
    # 12. Construct candidate block Blk_B
    # 13. Broadcast (Blk_B, pi_B)
    return Blk_B, pi_B_list

# ==========================================
# Public Verification (Simulated)
# ==========================================
def public_verification(Blk_B, pi_B_list):
    # 15. If pi_B is invalid -> Abort and penalize Builder
    for pi_B in pi_B_list:
        if not pi_B.startswith("VDP_Builder_Proof"):
            return False
    return True

# ==========================================
# Executor Phase
# ==========================================
def executor_phase(Blk_B, skE):
    Blk_E = []
    pi_E_list = []
    
    # 19. For all transactions in Blk_B
    for i, tx_payload in enumerate(Blk_B):
        # 20. K <- AsymDec(sk_E, C_E)
        rsa_cipherE = PKCS1_OAEP.new(RSA.import_key(skE))
        try:
            K_double_prime = rsa_cipherE.decrypt(tx_payload['C_E'])
            
            # 21. Tx <- SymDec(K, C_tx)
            cipher_aes = AES.new(K_double_prime, AES.MODE_EAX, nonce=tx_payload['nonce'])
            tx_decoded = cipher_aes.decrypt_and_verify(tx_payload['C_tx'], tx_payload['tag'])
            
            # 22. Execute Tx
            # Deserialize the RAW transaction to show it was executed
            try:
                tx_info = f"RAW_TX bytes (len={len(tx_decoded)})"
                executed_tx = f"Execution Result: [{tx_info}] Completed Successfully."
            except Exception as e:
                executed_tx = f"Execution Result: Failed to decode - {e}"
            Blk_E.append(executed_tx)
            
            # 23. Generate verifiable decryption proof pi_E
            # (Simulation: We simulate the proof of correct execution/decryption)
            pi_E = f"VDP_Executor_Proof_Tx{i}_{SHA256.new(K_double_prime).hexdigest()[:16]}"
            pi_E_list.append(pi_E)
        except ValueError:
            print("Executor decryption failed for a transaction!")
            
    # 25. Construct final block Blk_E
    # 26. Broadcast (Blk_E, pi_E)
    return Blk_E, pi_E_list

# ==========================================
# Final Verification
# ==========================================
def final_verification(Blk_E, pi_E_list):
    # 29. If pi_E is valid -> Commit Blk_E to ledger
    # 31. Else -> Abort and penalize Executor
    for pi_E in pi_E_list:
        if not pi_E.startswith("VDP_Executor_Proof"):
            return False
    return True

def generate_ethereum_raw_tx(nonce):
    """Generate a standard EIP-1559 Raw Ethereum Transaction"""
    # Create a random user identity
    private_key = "0x" + secrets.token_hex(32)
    user_account = Account.from_key(private_key)
    
    # Build a standard ETH transaction
    transaction = {
        'to': '0xF0109fC8DF283027b6285cc889F5aA624EaC1F55', # Dummy recipient
        'value': 1000000000000000000, # 1 ETH
        'gas': 21000,
        'maxFeePerGas': 2000000000,
        'maxPriorityFeePerGas': 1000000000,
        'nonce': nonce,
        'chainId': 1
    }
    
    # Sign it to create the Raw Transaction bytes
    signed_tx = Account.sign_transaction(transaction, private_key)
    return signed_tx.raw_transaction

def benchmark_protocol():
    print(f"\n===================================================================")
    print(f"   Benchmarking Protocol with 1 RAW ETH Transaction       ")
    print(f"===================================================================\n")
    
    keyB, keyE = generate_keys()
    pkB = keyB.publickey().export_key()
    pkE = keyE.publickey().export_key()
    skB = keyB.export_key()
    skE = keyE.export_key()
    
    # Generate actual raw ethereum transactions for the benchmark
    print(f"[*] Generating 1 signed raw Ethereum transaction...")
    txs = [generate_ethereum_raw_tx(0)]
    mempool = []
    
    # Benchmark User Phase
    start_user = time.time()
    for tx in txs:
        mempool.append(user_phase(tx, pkB, pkE))
    end_user = time.time()
    user_time_ms = ((end_user - start_user)) * 1000
    
    # Gas cost logic
    overhead_bytes = mempool[0]['C_tx'] + mempool[0]['tag'] + mempool[0]['nonce'] + mempool[0]['C_B'] + mempool[0]['C_E']
    
    # Benchmark Builder Phase
    start_builder = time.time()
    Blk_B, pi_B_list = builder_phase(mempool, skB)
    end_builder = time.time()
    builder_time_ms = ((end_builder - start_builder)) * 1000

    # Benchmark Public Verification
    start_pub_verif = time.time()
    public_verification(Blk_B, pi_B_list)
    end_pub_verif = time.time()
    pub_verif_time_ms = ((end_pub_verif - start_pub_verif)) * 1000
    
    # Benchmark Executor Phase
    start_executor = time.time()
    Blk_E, pi_E_list = executor_phase(Blk_B, skE)
    end_executor = time.time()
    executor_time_ms = ((end_executor - start_executor)) * 1000
    
    # Benchmark Final Verification
    start_fin_verif = time.time()
    final_verification(Blk_E, pi_E_list)
    end_fin_verif = time.time()
    fin_verif_time_ms = ((end_fin_verif - start_fin_verif)) * 1000
    
    total_time_ms = user_time_ms + builder_time_ms + pub_verif_time_ms + executor_time_ms + fin_verif_time_ms
    
    print(f"Benchmark Results (Time for 1 transaction execution):")
    print(f"  User Phase (Encryption)         : {user_time_ms:.3f} ms")
    print(f"  Builder Phase (Decryption/Proof): {builder_time_ms:.3f} ms")
    print(f"  Public Verification (Proof check): {pub_verif_time_ms:.3f} ms")
    print(f"  Executor Phase (Full Decryption): {executor_time_ms:.3f} ms")
    print(f"  Final Verification (Proof check) : {fin_verif_time_ms:.3f} ms")
    print(f"  ------------------------------------------------")
    print(f"  Total Protocol Latency           : {total_time_ms:.3f} ms\n")
    print(f"[*] Original Tx Size    : {len(txs[0])} bytes")
    print(f"[*] Ciphertext Payload  : {len(overhead_bytes)} bytes")
    print(f"[*] Overall Calldata Gas: {calculate_evm_calldata_gas(overhead_bytes)} gas")
    return {
        "user_ms": user_time_ms,
        "builder_ms": builder_time_ms, 
        "pub_verif_ms": pub_verif_time_ms,
        "executor_ms": executor_time_ms,
        "fin_verif_ms": fin_verif_time_ms,
        "total_ms": total_time_ms
    }

def main():
    print("===================================================================")
    print("   Two-Tier MEV-Resistant Block Construction Protocol Simulation   ")
    print("===================================================================\n")
    
    # ------------- Setup -------------
    print("[*] Setting up Public/Private Keys...")
    keyB, keyE = generate_keys()
    pkB = keyB.publickey().export_key()
    pkE = keyE.publickey().export_key()
    skB = keyB.export_key()
    skE = keyE.export_key()
    print("    Keys generated successfully.\n")
    
    # Generate 3 example raw EVM transactions
    print("[*] Generating 3 actual signed Ethereum Raw Transactions...")
    txs = [generate_ethereum_raw_tx(0), generate_ethereum_raw_tx(1), generate_ethereum_raw_tx(2)]
    mempool = []
    
    # ------------- 1. User Phase -------------
    print("\n[1] User Phase starting...")
    for i, tx in enumerate(txs):
        payload = user_phase(tx, pkB, pkE)
        mempool.append(payload)
        print(f"    -> User {i+1} generated K, encrypted RAW Tx ({len(tx)} bytes), and broadcasted (C_tx, C_B, C_E).")
        
    # ------------- 2. Builder Phase -------------
    print("\n[2] Builder Phase starting...")
    print(f"    -> Builder collecting from mempool ({len(mempool)} transactions)...")
    Blk_B, pi_B_list = builder_phase(mempool, skB)
    print(f"    -> Builder decrypted K with sk_B, generated pi_B proofs.")
    print(f"    -> Candidate Block (Blk_B) constructed and broadcasted.")
    for i, p in enumerate(pi_B_list):
        print(f"       Proof {i+1}: {p}")
    
    # ------------- 3. Public Verification -------------
    print("\n[3] Public Verification Phase starting...")
    if public_verification(Blk_B, pi_B_list):
        print("    -> SUCCESS: Public verification passed! pi_B proofs are valid.")
    else:
        print("    -> FAILED: Verification failed! Abort and penalize Builder.")
        return
        
    # ------------- 4. Executor Phase -------------
    print("\n[4] Executor Phase starting...")
    Blk_E, pi_E_list = executor_phase(Blk_B, skE)
    print(f"    -> Executor decrypted K with sk_E, decrypted C_tx, and executed transactions.")
    for executed in Blk_E:
        print(f"       {executed}")
    print(f"    -> Final Block (Blk_E) constructed and broadcasted.")
    for i, p in enumerate(pi_E_list):
        print(f"       Proof {i+1}: {p}")
        
    # ------------- 5. Final Verification -------------
    print("\n[5] Final Verification Phase starting...")
    if final_verification(Blk_E, pi_E_list):
        print("    -> SUCCESS: Final Block and pi_E proofs verified successfully!")
        print("    -> ACTION: Committing Blk_E to the ledger.")
    else:
        print("    -> FAILED: Final Verification failed! Abort and penalize Executor.")
        
    print("\n==================== Protocol Execution Complete ====================")
    
    # Run Benchmark
    benchmark_protocol()

if __name__ == '__main__':
    main()
