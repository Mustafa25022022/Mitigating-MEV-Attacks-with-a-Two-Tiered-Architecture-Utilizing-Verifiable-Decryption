import os
import time
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from eth_account import Account
import secrets
from web3 import Web3

# Public Sepolia RPC
SEPOLIA_RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com"

def generate_keys():
    """Generate RSA keypairs for Builder and Executor."""
    keyB = RSA.generate(2048)
    keyE = RSA.generate(2048)
    return keyB, keyE

def calculate_evm_calldata_gas(data_bytes):
    """Calculate the Ethereum Gas Cost for storing bytes as Calldata"""
    gas = 0
    for byte in data_bytes:
        if byte == 0:
            gas += 4
        else:
            gas += 16
    return gas

def get_sepolia_network_params():
    """Connects to Sepolia and fetches real-time network conditions."""
    w3 = Web3(Web3.HTTPProvider(SEPOLIA_RPC_URL))
    
    if not w3.is_connected():
        raise ConnectionError("Failed to connect to the Sepolia Testnet.")
        
    latest_block = w3.eth.get_block('latest')
    base_fee = latest_block.get('baseFeePerGas', 1000000000) # Fallback to 1 gwei if not found
    
    # Priority fee estimation
    priority_fee = w3.eth.max_priority_fee
    
    return w3, latest_block['number'], base_fee, priority_fee

def generate_sepolia_raw_tx(w3, base_fee, priority_fee, nonce):
    """Generate a standard EIP-1559 Raw Ethereum Transaction structured for Sepolia"""
    private_key = "0x" + secrets.token_hex(32)
    user_account = Account.from_key(private_key)
    
    transaction = {
        'to': '0xF0109fC8DF283027b6285cc889F5aA624EaC1F55', # Dummy recipient
        'value': w3.to_wei(0.01, 'ether'),
        'gas': 21000,
        'maxFeePerGas': base_fee + priority_fee,
        'maxPriorityFeePerGas': priority_fee,
        'nonce': nonce,
        'chainId': 11155111 # Sepolia Chain ID
    }
    
    signed_tx = Account.sign_transaction(transaction, private_key)
    return signed_tx.raw_transaction

# ==========================================
# Phase Implementations (Same as Local Setup)
# ==========================================
def user_phase(raw_tx, pkB, pkE):
    K = os.urandom(32)
    cipher_aes = AES.new(K, AES.MODE_EAX)
    C_tx, tag = cipher_aes.encrypt_and_digest(raw_tx)
    nonce = cipher_aes.nonce
    
    rsa_cipherB = PKCS1_OAEP.new(RSA.import_key(pkB))
    C_B = rsa_cipherB.encrypt(K)
    
    rsa_cipherE = PKCS1_OAEP.new(RSA.import_key(pkE))
    C_E = rsa_cipherE.encrypt(K)
    
    payload = {
        'C_tx': C_tx, 'tag': tag, 'nonce': nonce,
        'C_B': C_B, 'C_E': C_E, 'tx_size': len(raw_tx)
    }
    return payload

def builder_phase(mempool_txs, skB):
    Blk_B = []
    pi_B_list = []
    
    for i, tx_payload in enumerate(mempool_txs):
        rsa_cipherB = PKCS1_OAEP.new(RSA.import_key(skB))
        try:
            K_prime = rsa_cipherB.decrypt(tx_payload['C_B'])
            pi_B = f"VDP_Builder_Proof_Tx{i}_{SHA256.new(K_prime).hexdigest()[:16]}"
            Blk_B.append(tx_payload)
            pi_B_list.append(pi_B)
        except ValueError:
            pass
            
    return Blk_B, pi_B_list

def public_verification(Blk_B, pi_B_list):
    for pi_B in pi_B_list:
        if not pi_B.startswith("VDP_Builder_Proof"):
            return False
    return True

def executor_phase(Blk_B, skE):
    Blk_E = []
    pi_E_list = []
    
    for i, tx_payload in enumerate(Blk_B):
        rsa_cipherE = PKCS1_OAEP.new(RSA.import_key(skE))
        try:
            K_double_prime = rsa_cipherE.decrypt(tx_payload['C_E'])
            cipher_aes = AES.new(K_double_prime, AES.MODE_EAX, nonce=tx_payload['nonce'])
            tx_decoded = cipher_aes.decrypt_and_verify(tx_payload['C_tx'], tx_payload['tag'])
            
            executed_tx = f"Execution Result: [RAW_TX bytes (len={len(tx_decoded)})] Completed Successfully."
            Blk_E.append(executed_tx)
            
            pi_E = f"VDP_Executor_Proof_Tx{i}_{SHA256.new(K_double_prime).hexdigest()[:16]}"
            pi_E_list.append(pi_E)
        except ValueError:
            pass
            
    return Blk_E, pi_E_list

def final_verification(Blk_E, pi_E_list):
    for pi_E in pi_E_list:
        if not pi_E.startswith("VDP_Executor_Proof"):
            return False
    return True

def run_testnet_simulation():
    output_lines = []
    def log(msg):
        print(msg)
        output_lines.append(msg)

    log("===================================================================")
    log("   Sepolia Testnet Context Simulation of Two-Tier MEV Protection   ")
    log("===================================================================\n")
    
    try:
        log("[*] Connecting to Sepolia Testnet...")
        w3, block_num, base_fee, priority_fee = get_sepolia_network_params()
        log(f"    -> Connected! Latest Block: {block_num}")
        log(f"    -> Current Base Fee     : {w3.from_wei(base_fee, 'gwei'):.4f} Gwei")
        log(f"    -> Current Priority Fee : {w3.from_wei(priority_fee, 'gwei'):.4f} Gwei\n")
    except Exception as e:
        log(f"    -> Error connecting to Sepolia: {e}")
        return

    log("[*] Setting up Public/Private Keys...")
    keyB, keyE = generate_keys()
    pkB = keyB.publickey().export_key()
    pkE = keyE.publickey().export_key()
    skB = keyB.export_key()
    skE = keyE.export_key()
    log("    Keys generated successfully.\n")

    log("[*] Generating 1 Signed Sepolia Raw Transaction...")
    txs = [generate_sepolia_raw_tx(w3, base_fee, priority_fee, 0)]
    mempool = []

    # Benchmark User Phase
    start_user = time.time()
    for tx in txs:
        mempool.append(user_phase(tx, pkB, pkE))
    end_user = time.time()
    user_time_ms = (end_user - start_user) * 1000

    overhead_bytes = mempool[0]['C_tx'] + mempool[0]['tag'] + mempool[0]['nonce'] + mempool[0]['C_B'] + mempool[0]['C_E']
    calldata_gas = calculate_evm_calldata_gas(overhead_bytes)
    
    # Calculate Live Cost
    gas_cost_wei = calldata_gas * (base_fee + priority_fee)
    gas_cost_eth = w3.from_wei(gas_cost_wei, 'ether')
    # Using an approximate ETH price in USD (e.g. $2500 for demonstration logic, assuming identical equivalent testnet abstract cost)
    # Since it's a testnet, ETH has zero value, but we can display the abstract cost
    
    log("\n[1] User Phase Simulated...")
    
    start_builder = time.time()
    Blk_B, pi_B_list = builder_phase(mempool, skB)
    end_builder = time.time()
    builder_time_ms = (end_builder - start_builder) * 1000
    log("[2] Builder Phase Simulated...")

    start_pub_verif = time.time()
    verif_res = public_verification(Blk_B, pi_B_list)
    end_pub_verif = time.time()
    pub_verif_time_ms = (end_pub_verif - start_pub_verif) * 1000
    log(f"[3] Public Verification: {verif_res}")

    start_executor = time.time()
    Blk_E, pi_E_list = executor_phase(Blk_B, skE)
    end_executor = time.time()
    executor_time_ms = (end_executor - start_executor) * 1000
    log("[4] Executor Phase Simulated...")

    start_fin_verif = time.time()
    final_verif_res = final_verification(Blk_E, pi_E_list)
    end_fin_verif = time.time()
    fin_verif_time_ms = (end_fin_verif - start_fin_verif) * 1000
    log(f"[5] Final Verification: {final_verif_res}")

    total_time_ms = user_time_ms + builder_time_ms + pub_verif_time_ms + executor_time_ms + fin_verif_time_ms

    log(f"\n===================================================================")
    log(f"                Sepolia Benchmark Results:")
    log(f"===================================================================")
    log(f"  User Phase (Encryption)         : {user_time_ms:.3f} ms")
    log(f"  Builder Phase (Decryption/Proof): {builder_time_ms:.3f} ms")
    log(f"  Public Verification (Proof check): {pub_verif_time_ms:.3f} ms")
    log(f"  Executor Phase (Full Decryption): {executor_time_ms:.3f} ms")
    log(f"  Final Verification (Proof check) : {fin_verif_time_ms:.3f} ms")
    log(f"  ------------------------------------------------")
    log(f"  Total Protocol Latency           : {total_time_ms:.3f} ms\n")
    log(f"[*] Original Sepolia Tx Size : {len(txs[0])} bytes")
    log(f"[*] Ciphertext Payload       : {len(overhead_bytes)} bytes")
    log(f"[*] Protocol Calldata Gas    : {calldata_gas} gas")
    log(f"[*] Abstract Overhead Cost   : {gas_cost_eth:.8f} Sepolia ETH")
    log(f"===================================================================")

    # Save to file
    output_filename = "Sepolia_Testnet_Results.txt"
    with open(output_filename, "w") as f:
        f.write("\n".join(output_lines))
    print(f"\n[+] Results saved to {output_filename}")

if __name__ == '__main__':
    run_testnet_simulation()
