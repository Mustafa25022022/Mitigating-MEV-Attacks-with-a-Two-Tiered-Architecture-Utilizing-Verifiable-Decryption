# Mitigating-MEV-Attacks-with-a-Two-Tiered-Architecture-Utilizing-Verifiable-Decryption

Mitigating MEV Attacks with a Two-Tiered Architecture  Utilizing Verifiable Decryption

This repository contains the Python implementation files used for the proposal model in the manuscript titled "Mitigating MEV Attacks with a Two-Tiered Architecture Utilizing Verifiable Decryption".

## Research Use Notice

Please note that the code and experiments provided in this repository are intended for research purposes only. They have not been fully validated and should be used with caution. Users are encouraged to review the code and test it further before applying it in production environments.

## Python Implementation Files

- `Algorithm Implementation.py`: Contains the main core algorithm implementation.
- `benchmark_base_encryption.py`: Base encryption benchmarks for User, Builder, and Executor key exchanges. Evaluates encryption and decryption latencies.
- `benchmark_builder_tampering.py`: Evaluates scenarios where the Builder acts maliciously and tempers with the transaction ciphertext.
- `benchmark_executor_tampering.py`: Evaluates scenarios where the Executor tampers with the original transaction data.
- `benchmark_community_verification.py`: Measures overhead on verifying builder/executor validity based on cryptographic hashes.
- `local_eth_utils.py`: Contains standard EIP-1559 Raw Ethereum Transaction generation utilities used across all benchmarks.
- `Statistics Matrix.py`: Implementation for statistical analysis and metrics.
- `Probability Rate of MEV attacks.py`: Implementation focusing on the statistical probability of succeeding in an MEV attack scenario.

## Description

These files contain the necessary code to replicate the experiments and results presented in our manuscript. Each file corresponds to different cases and scenarios we analyzed during our research.

## Two-Tier Protocol Architecture

The algorithm operates on a "commit-and-reveal" or verifiable decryption approach.

```mermaid
sequenceDiagram
    participant User
    participant Mempool
    participant Builder
    participant Executor
    
    Note over User: Generates symmetric key K<br/>Encrypts Tx with K -> C_tx
    Note over User: Encrypts K for Builder -> C_B<br/>Encrypts K for Executor -> C_E
    
    User->>Mempool: Broadcast (C_tx, C_B, C_E)
    
    Mempool->>Builder: Collect Tx
    Note over Builder: Decrypts C_B to get K<br/>(Blindly) orders transactions
    Note over Builder: Generates proofs pi_B
    Builder->>Mempool: Broadcast Candidate Block (Blk_B, pi_B)
    
    Note over Mempool: Public Verification of Builder's proofs
    
    Mempool->>Executor: Verified Candidate Block
    Note over Executor: Decrypts C_E to get K<br/>Decrypts C_tx to fully reveal Tx
    Note over Executor: Executes Tx in exact order set by Builder
    Note over Executor: Generates proofs pi_E
    Executor->>Mempool: Broadcast Final Block (Blk_E, pi_E)
    
    Note over Mempool: Final Verification of Executor's proofs<br/>Commit Block to Ledger
```

## Benchmark Results

Below are the single-execution benchmark results of simulating the **Two-Tier MEV-Resistant Block Construction Protocol** with a randomly generated standard Raw Ethereum Transaction.

In addition to timing, the protocols tracked the EVM `Ciphertext Payload` per transaction which evaluates to exactly **661-693 bytes** overhead given AES-EAX and RSA-2048 parameters. Storing this equivalent overhead as `Calldata` during transaction initiation on mainnet would cost theoretically ~`10492-11064 gas`.

```text
===================================================================
   Benchmarking Protocol with 1 RAW ETH Transaction       
===================================================================

[*] Generating 1 signed raw Ethereum transaction...
Benchmark Results (Time for 1 transaction execution):
  User Phase (Encryption)         : 3.026 ms
  Builder Phase (Decryption/Proof): 40.618 ms
  Public Verification (Proof check): 0.000 ms
  Executor Phase (Full Decryption): 41.565 ms
  Final Verification (Proof check) : 0.000 ms
  ------------------------------------------------
  Total Protocol Latency           : 85.209 ms

[*] Original Tx Size    : 117 bytes
[*] Ciphertext Payload  : 661 bytes
[*] Overall Calldata Gas: 10492 gas
===================================================================

===================================================================
              Benchmark: Base Encryption Latency                   
===================================================================

[*] Transaction encryption and integrity check executed.
[*] Original Tx Size  : 117 bytes
[*] Ciphertext Size   : 693 bytes
[*] Encryption Time   : 7.302 ms
[*] Decryption Time   : 4.084 ms
[*] Integrity Passed  : True

[*] Theoretical Gas Cost Overhead (Calldata): 11064 gas
===================================================================

===================================================================
              Benchmark: Builder Tampering Detection               
===================================================================

[*] Tampering detection checked.
[*] Tampering Detected : True
[*] Integrity Passed   : False
[*] Overall Execution  : 844.421 ms
[*] Tamper Check Time  : 844.421 ms
[*] Original Tx Size   : 117 bytes
[*] Ciphertext Size    : 693 bytes

[*] Theoretical Gas Cost Overhead (Calldata): 11004 gas
===================================================================

===================================================================
              Benchmark: Executor Tampering Detection              
===================================================================

[*] Tampering detection checked.
[*] Result Message     : Tampering not detected
[*] Integrity Passed   : False
[*] Encryption Time    : 9.518 ms
[*] Tamper Action Time : 0.000 ms
[*] Integrity Time     : 0.000 ms
[*] Original Tx Size   : 117 bytes
[*] Ciphertext Size    : 693 bytes

[*] Theoretical Gas Cost Overhead (Calldata): 11016 gas
===================================================================

===================================================================
              Benchmark: Community Verification Latency            
===================================================================

[*] Community Verification finished.
[*] Builder Verified   : True
[*] Executor Verified  : False
[*] Verification Time  : 0.000 ms
[*] Key Gen Time       : 370.096 ms
[*] Original Tx Size   : 117 bytes
[*] Ciphertext Size    : 661 bytes

[*] Theoretical Gas Cost Overhead (Calldata): 10540 gas
===================================================================
```
