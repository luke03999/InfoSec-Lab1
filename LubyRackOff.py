# TASK 3: LubyRackOff

import json
from GGM import ggm_prf

JSON_PATH = "vectors/lab1task3.json"


# Computes the XOR between two byte sequences of the same length.
def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("Inputs must have the same length")
    return bytes(x ^ y for x, y in zip(a, b))

# Implements a Luby-Rackoff block cipher using a Feistel network structure.
class LubyRackoffCipher:
    HALF_BLOCK_SIZE = 10
    BLOCK_SIZE = 20

    # Initializes the cipher with the provided key and number of rounds (in our case 4 rounds specified in the task 3).
    def __init__(self, key: bytes, rounds: int = 4):
        if rounds < 1:
            raise ValueError("Rounds must be at least 1")

        # The total key length depends on the number of rounds
        expected_key_len = rounds * self.HALF_BLOCK_SIZE
        if len(key) != expected_key_len:
            raise ValueError(
                f"Key must be {expected_key_len} bytes for {rounds} rounds"
            )

        self.rounds = rounds
        # Split the main key into separate subkeys for each round
        self.round_keys = [
            key[i * self.HALF_BLOCK_SIZE:(i + 1) * self.HALF_BLOCK_SIZE]
            for i in range(rounds)
        ]

    # Ensures that the input block matches the expected block size.
    def _validate_block(self, block: bytes, name: str) -> None:
        if len(block) != self.BLOCK_SIZE:
            # Raise an error if the blocks have different size
            raise ValueError(f"{name} must be {self.BLOCK_SIZE} bytes")

    # Splits a full block into two equal halves (left and right).
    def _split_block(self, block: bytes) -> tuple[bytes, bytes]:
        return block[:self.HALF_BLOCK_SIZE], block[self.HALF_BLOCK_SIZE:]

    # Encrypts a single plaintext block using the Feistel network.
    def encrypt(self, plaintext: bytes) -> bytes:
        self._validate_block(plaintext, "Plaintext")

        left, right = self._split_block(plaintext)

        # Apply the Feistel round function for the configured number of rounds
        for round_key in self.round_keys:
            # The PRF takes the round key and the right half
            f_out = ggm_prf(round_key, right)
            # The new left becomes the old right, new right is XORed with the PRF output
            left, right = right, xor_bytes(left, f_out)

        return left + right


    # Decrypts a single ciphertext block using the reversed Feistel network.
    def decrypt(self, ciphertext: bytes) -> bytes:
        self._validate_block(ciphertext, "Ciphertext")

        left, right = self._split_block(ciphertext)

        # To decrypt, apply the round keys in reverse order
        for round_key in reversed(self.round_keys):
            # The PRF still takes the round key, but now operates on the left half
            f_out = ggm_prf(round_key, left)
            # Reverse the swap: old left is the new right XORed with the PRF output, new right is the old left
            left, right = xor_bytes(right, f_out), left

        return left + right


if __name__ == '__main__':
    # Load test vectors "lab1task3.json"
    with open(JSON_PATH, "r") as f:
        vectors = json.load(f)

    print("Start Task 3: Luby-Rackoff")

    # Run tests over all vectors
    for tv in vectors:
        cipher = LubyRackoffCipher(bytes.fromhex(tv["key"]))
        msg = bytes.fromhex(tv["msg"])
        expected_ct = bytes.fromhex(tv["ct"])

        # Test encryption and decryption
        ct = cipher.encrypt(msg)
        dec = cipher.decrypt(ct)

        enc_ok, dec_ok = (ct == expected_ct), (dec == msg)
        print(f"    Test {tv['number']}: Encryption {'PASS' if enc_ok else 'FAIL'} | Decryption {'PASS' if dec_ok else 'FAIL'}")

        # Provide debug info only if tests fail
        if not enc_ok or not dec_ok:
            print(f"  Got CipherText: {ct.hex()} (Expected: {expected_ct.hex()})") if not enc_ok else None
            print(f"  Decrypt failed: {dec.hex()}") if not dec_ok else None

    print("End Task 3: Luby-Rackoff")