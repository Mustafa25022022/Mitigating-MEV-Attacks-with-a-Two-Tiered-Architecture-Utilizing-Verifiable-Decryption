import os
import time
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_keys():
    """Generate RSA keypairs for Builder and Executor."""
    keyB = RSA.generate(2048)
    keyE = RSA.generate(2048)
    return keyB, keyE

# ==========================================
# User Phase
# ==========================================
def user_phase(tx, pkB, pkE):
    # 1. Generate fresh symmetric key K (AES-256)
    K = os.urandom(32)
    
    # 2. C_tx <- SymEnc(K, Tx)
    cipher_aes = AES.new(K, AES.MODE_EAX)
    C_tx, tag = cipher_aes.encrypt_and_digest(tx.encode('utf-8'))
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
        'tx_size': len(tx.encode('utf-8'))
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
            executed_tx = f"Execution Result: [{tx_decoded.decode('utf-8')}] Completed Successfully."
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

def benchmark_protocol(num_txs=1000):
    print(f"\n===================================================================")
    print(f"   Benchmarking Protocol with {num_txs} Transactions               ")
    print(f"===================================================================\n")
    
    keyB, keyE = generate_keys()
    pkB = keyB.publickey().export_key()
    pkE = keyE.publickey().export_key()
    skB = keyB.export_key()
    skE = keyE.export_key()
    
    # Generate 1000 dummy transactions of different sizes
    txs = [f"Tx_Dummy_Data_Payload_{i}" * 5 for i in range(num_txs)]
    mempool = []
    
    # Benchmark User Phase
    start_user = time.time()
    for tx in txs:
        mempool.append(user_phase(tx, pkB, pkE))
    end_user = time.time()
    user_time_ms = ((end_user - start_user) / num_txs) * 1000
    
    # Benchmark Builder Phase
    start_builder = time.time()
    Blk_B, pi_B_list = builder_phase(mempool, skB)
    end_builder = time.time()
    builder_time_ms = ((end_builder - start_builder) / num_txs) * 1000

    # Benchmark Public Verification
    start_pub_verif = time.time()
    public_verification(Blk_B, pi_B_list)
    end_pub_verif = time.time()
    pub_verif_time_ms = ((end_pub_verif - start_pub_verif) / num_txs) * 1000
    
    # Benchmark Executor Phase
    start_executor = time.time()
    Blk_E, pi_E_list = executor_phase(Blk_B, skE)
    end_executor = time.time()
    executor_time_ms = ((end_executor - start_executor) / num_txs) * 1000
    
    # Benchmark Final Verification
    start_fin_verif = time.time()
    final_verification(Blk_E, pi_E_list)
    end_fin_verif = time.time()
    fin_verif_time_ms = ((end_fin_verif - start_fin_verif) / num_txs) * 1000
    
    total_time_ms = user_time_ms + builder_time_ms + pub_verif_time_ms + executor_time_ms + fin_verif_time_ms
    
    print(f"Benchmark Results (Average time per transaction over {num_txs} runs):")
    print(f"  User Phase (Encryption)         : {user_time_ms:.3f} ms")
    print(f"  Builder Phase (Decryption/Proof): {builder_time_ms:.3f} ms")
    print(f"  Public Verification (Proof check): {pub_verif_time_ms:.3f} ms")
    print(f"  Executor Phase (Full Decryption): {executor_time_ms:.3f} ms")
    print(f"  Final Verification (Proof check) : {fin_verif_time_ms:.3f} ms")
    print(f"  ------------------------------------------------")
    print(f"  Total Protocol Overhead per Tx   : {total_time_ms:.3f} ms\n")
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
    
    # Example Transactions
    txs = [
        "Swap 10 ETH for 20,000 USDT on Uniswap", 
        "Mint 1 BAYC NFT", 
        "Transfer 50 USDC to Alice"
    ]
    mempool = []
    
    # ------------- 1. User Phase -------------
    print("[1] User Phase starting...")
    for i, tx in enumerate(txs):
        payload = user_phase(tx, pkB, pkE)
        mempool.append(payload)
        print(f"    -> User {i+1} generated K, encrypted Tx, and broadcasted (C_tx, C_B, C_E).")
        
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
    benchmark_protocol(1000)

if __name__ == '__main__':
    main()
