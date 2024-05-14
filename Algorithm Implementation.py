Python 3.12.2 (tags/v3.12.2:6abddd9, Feb  6 2024, 21:26:36) [MSC v.1937 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license()" for more information.
import os
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def encrypt_by_user(tx, pkB, pkE):
    KE = os.urandom(32)
    KB = os.urandom(32)
    hE = SHA256.new(tx.encode()).digest()
    mE = tx.encode() + hE
    cipherE = AES.new(KE, AES.MODE_EAX)
    CE1, tagE = cipherE.encrypt_and_digest(mE)
    hB = SHA256.new(CE1).digest()
    mB = CE1 + hB
    cipherB = AES.new(KB, AES.MODE_EAX)
    CB1, tagB = cipherB.encrypt_and_digest(mB)
    rsa_cipherB = PKCS1_OAEP.new(RSA.importKey(pkB))
    CB2 = rsa_cipherB.encrypt(KB)
    rsa_cipherE = PKCS1_OAEP.new(RSA.importKey(pkE))
    CE2 = rsa_cipherE.encrypt(KE)
    return CB1, CB2, CE2

def decrypt_by_builder(CB1, CB2, skB):
    try:
        with PKCS1_OAEP.new(RSA.importKey(skB)) as rsa_cipherB:
            KB_prime = rsa_cipherB.decrypt(CB2)
        KB_prime = SHA256.new(KB_prime).digest()
        with AES.new(KB_prime, AES.MODE_EAX) as cipherB:
            mB = cipherB.decrypt_and_verify(CB1[:-16], CB1[-16:])
        CE1, hB = mB[:-32], mB[-32:]
        if hB == SHA256.new(CE1).digest():
            return CE1
        else:
            return None
    except (ValueError, KeyError) as e:
        print(f"Decryption failed: {e}")
        return None

def decrypt_by_executor(CE1, CE2, skE):
    try:
        with PKCS1_OAEP.new(RSA.importKey(skE)) as rsa_cipherE:
            KE_prime = rsa_cipherE.decrypt(CE2)
        KE_prime = SHA256.new(KE_prime).digest()
...         with AES.new(KE_prime, AES.MODE_EAX) as cipherE:
...             mE = cipherE.decrypt_and_verify(CE1[:-16], CE1[-16:])
...         tx, hE = mE[:-32], mE[-32:]
...         if hE == SHA256.new(tx).digest():
...             return tx
...         else:
...             return None
...     except (ValueError, KeyError) as e:
...         print(f"Decryption failed: {e}")
...         return None
... 
... def verify_by_community(KE_prime, CB1, CB2, pkB, CE1, CE2, pkE):
...     # Verification of builder's calculations
...     KB = SHA256.new(KE_prime).digest()
...     CE1_prime, hB = SymDec(KB, CB1)
...     builder_verification = hB == SHA256.new(CE1_prime).digest()
... 
...     # Verification of executor's calculations
...     KE = SHA256.new(KE_prime).digest()
...     tx, hE = SymDec(KE, CE1)
...     executor_verification = hE == SHA256.new(tx).digest()
... 
...     return builder_verification, executor_verification
... 
... # Example usage
... tx = "Hello, this is a test transaction."
... keyB = RSA.generate(2048)
... keyE = RSA.generate(2048)
... pkB = keyB.publickey().exportKey()
... pkE = keyE.publickey().exportKey()
... 
... try:
...     CB1, CB2, CE2 = encrypt_by_user(tx, pkB, pkE)
...     print("Encryption successful.")
...     print("CB1:", CB1)
...     print("CB2:", CB2)
...     print("CE2:", CE2)
... except Exception as e:
...     print("Encryption failed with exception:", e)
