import secrets
from eth_account import Account

def generate_ethereum_raw_tx(nonce):
    """Generate a standard EIP-1559 Raw Ethereum Transaction"""
    # Create a random user identity
    private_key = "0x" + secrets.token_hex(32)
    # user_account = Account.from_key(private_key) # Only needed if we wanted to extract the address
    
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

def calculate_evm_calldata_gas(data_bytes):
    """Calculate the Ethereum Gas Cost for storing bytes as Calldata"""
    gas = 0
    for byte in data_bytes:
        if byte == 0:
            gas += 4
        else:
            gas += 16
    return gas
