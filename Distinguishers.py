# Task 4: Luby-Rackoff distinguishers.

import os
import secrets
from LubyRackOff import LubyRackoffCipher, xor_bytes

HALF = 10

# 2-round Feistel distinguisher (CPA).
def two_round_distinguisher(enc) -> str:
    # Pick two messages with the same right half but different left halves.
    L, L2, R = secrets.token_bytes(HALF), secrets.token_bytes(HALF), secrets.token_bytes(HALF)
    
    # Get the ciphertexts.
    C0, C1 = enc(L + R), enc(L2 + R)
    
    # In a 2-round Feistel, the XOR difference of the left halves doesn't change.
    # If the property holds, it's our cipher, not random noise.
    return "feistel" if xor_bytes(C0[:HALF], C1[:HALF]) == xor_bytes(L, L2) else "random"

# 3-round Feistel distinguisher (CCA).
def three_round_distinguisher(enc, dec) -> str:
    # Start again with two messages differing only in the left half.
    L, L2, R = secrets.token_bytes(HALF), secrets.token_bytes(HALF), secrets.token_bytes(HALF)
    
    # Keep track of the XOR difference of the left halves.
    delta = xor_bytes(L, L2)
    
    # First, encrypt them normally.
    C0, C1 = enc(L + R), enc(L2 + R)
    
    # The trick: XOR the ciphertext's right halves with our delta,
    # and ask the oracle to decrypt them.
    D0 = dec(C0[:HALF] + xor_bytes(C0[HALF:], delta))
    D1 = dec(C1[:HALF] + xor_bytes(C1[HALF:], delta))
    
    # In a 3-round Feistel, this tweak magically makes the decrypted right halves identical.
    return "feistel" if D0[HALF:] == D1[HALF:] else "random"


if __name__ == "__main__":
    N = 3

    k2 = LubyRackoffCipher(os.urandom(HALF * 2), rounds=2)
    k3 = LubyRackoffCipher(os.urandom(HALF * 3), rounds=3)
    k4 = LubyRackoffCipher(os.urandom(HALF * 4), rounds=4)

    print("2-round distinguisher")
    print(f"  F(2): {[two_round_distinguisher(k2.encrypt) for _ in range(N)]}  (expect: feistel)")
    print(f"  F(4): {[two_round_distinguisher(k4.encrypt) for _ in range(N)]}  (expect: random)")

    print("3-round distinguisher")
    print(f"  F(3): {[three_round_distinguisher(k3.encrypt, k3.decrypt) for _ in range(N)]}  (expect: feistel)")
    print(f"  F(4): {[three_round_distinguisher(k4.encrypt, k4.decrypt) for _ in range(N)]}  (expect: random)")
