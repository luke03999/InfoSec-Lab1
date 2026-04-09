"""
Task 4 — Distinguishers for 2-round and 3-round Luby-Rackoff (Feistel) cipher.

A distinguisher is an algorithm that tells apart a cipher from a truly random
permutation by exploiting a structural property of the Feistel construction.

--- 2-round distinguisher (encryption oracle only) ---

After 2 Feistel rounds, encrypting (L, R) gives:
  C = ( L XOR F1(R),   R XOR F2(L XOR F1(R)) )

The left half of C is L XOR F1(R). If we encrypt two messages (L0, R) and
(L1, R) sharing the same right half R, then F1(R) cancels out:
  left(C0) XOR left(C1) = L0 XOR L1

A random permutation satisfies this with probability ~1/2^80 → negligible.

--- 3-round distinguisher (encryption + decryption oracle) ---

After 3 rounds, encrypting (L, R) gives C = (S, T) where:
  S = R  XOR F2(L XOR F1(R))
  T = (L XOR F1(R))  XOR F3(S)

Encrypt (L0, R) and (L1, R) → C0 = (S0, T0), C1 = (S1, T1).
Let Δ = L0 XOR L1. Decrypt C0' = (S0, T0 XOR Δ) and C1' = (S1, T1 XOR Δ).

After working through the algebra, the right halves of the decrypted blocks
are equal: right(D0) == right(D1). This holds because the XOR-Δ shift on T
exactly cancels the difference introduced by L0 vs L1 in the last round.

A random permutation satisfies this with probability ~1/2^80 → negligible.
"""

import secrets
from LubyRackOff import LubyRackoffCipher, xor_bytes

# Global variable
HALF = 10
BLOCK = 20


def rand_half() -> bytes:
    return secrets.token_bytes(HALF)


def split(block: bytes) -> tuple[bytes, bytes]:
    return block[:HALF], block[HALF:]


# ---------------------------------------------------------------------------
# 2-round distinguisher
# ---------------------------------------------------------------------------

def two_round_distinguisher(enc) -> bool:
    """
    Query enc with two messages sharing the same right half.
    For F(2): left(C0) XOR left(C1) == L0 XOR L1  (always)
    For random permutation: holds with prob ~1/2^80
    """


    R  = rand_half()
    L0 = rand_half()
    L1 = rand_half()

    C0 = enc(L0 + R)
    C1 = enc(L1 + R)

    left0, _ = split(C0)
    left1, _ = split(C1)

    return xor_bytes(left0, left1) == xor_bytes(L0, L1)


# ---------------------------------------------------------------------------
# 3-round distinguisher
# ---------------------------------------------------------------------------

def three_round_distinguisher(enc, dec) -> bool:
    """
    Query enc with two messages sharing the same right half, then
    query dec with the ciphertexts XOR-shifted by Δ = L0 XOR L1.
    For F(3): right(D0) == right(D1)  (always)
    For random permutation: holds with prob ~1/2^80
    """
    R  = rand_half()
    L0 = rand_half()
    L1 = rand_half()
    delta = xor_bytes(L0, L1)

    C0 = enc(L0 + R)
    C1 = enc(L1 + R)

    S0, T0 = split(C0)
    S1, T1 = split(C1)

    # Shift the right half of each ciphertext by delta before decrypting
    D0 = dec(S0 + xor_bytes(T0, delta))
    D1 = dec(S1 + xor_bytes(T1, delta))

    _, R0 = split(D0)
    _, R1 = split(D1)

    return R0 == R1


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # --- 2-round ---
    key2 = secrets.token_bytes(HALF * 2)
    cipher2 = LubyRackoffCipher(key2, rounds=2)
    result2 = two_round_distinguisher(cipher2.encrypt)
    print(f"2-round distinguisher on F(2): {'MATCH (cipher detected)' if result2 else 'NO MATCH'}")

    # Sanity check: should fail on a 4-round cipher (behaves like random permutation)
    key4 = secrets.token_bytes(HALF * 4)
    cipher4 = LubyRackoffCipher(key4, rounds=4)
    hits = sum(two_round_distinguisher(cipher4.encrypt) for _ in range(100)

)
    print(f"2-round distinguisher on F(4): {hits}/100 matches (expected ~50 by chance)")

    print()

    # --- 3-round ---
    key3 = secrets.token_bytes(HALF * 3)
    cipher3 = LubyRackoffCipher(key3, rounds=3)
    result3 = three_round_distinguisher(cipher3.encrypt, cipher3.decrypt)
    print(f"3-round distinguisher on F(3): {'MATCH (cipher detected)' if result3 else 'NO MATCH'}")

    # Sanity check: should fail on F(4)
    hits = sum(three_round_distinguisher(cipher4.encrypt, cipher4.decrypt) for _ in range(100))
    print(f"3-round distinguisher on F(4): {hits}/100 matches (expected ~50 by chance)")