# TASK 1: Implement Trivium Stream Cipher
import json
from utility import bytes_to_bits

JSON_PATH = "vectors/lab1task1.json"

# Implementation of the Trivium stream cipher.
class Trivium:

    # Initializes the 288-bit internal state using the key and IV.
    def __init__(self, key: bytes, iv: bytes):
        key_bits = bytes_to_bits(key)
        iv_bits = bytes_to_bits(iv)

        # Reverse bits for Key and IV 
        self.key = key_bits[::-1]
        self.iv = iv_bits[::-1]

        # Initialize 288-bit state array with zeros
        self.state = [0] * 288

        # Load Key into first register (s1..s80)
        for i in range(0, 80):
            self.state[i] = self.key[i]

        # Load IV into second register (s94..s173)
        for i in range(93, 173):
            self.state[i] = self.iv[i - 93]

        # Set specific bits for third register
        self.state[285] = self.state[286] = self.state[287] = 1

        # Perform the 4 * 288 initialization cycles
        for _ in range(4 * 288):
            self._gen_bit()

    # Performs one cycle of the shift register and outputs a key stream bit.
    def _gen_bit(self):
        s = self.state

        # Compute outputs for the three registers
        t1 = s[65] ^ s[92]
        t2 = s[161] ^ s[176]
        t3 = s[242] ^ s[287]

        # Compute key stream bit
        z = t1 ^ t2 ^ t3

        # Add non-linear feedback
        t1 = t1 ^ (s[90] & s[91]) ^ s[170]
        t2 = t2 ^ (s[174] & s[175]) ^ s[263]
        t3 = t3 ^ (s[285] & s[286]) ^ s[68]

        # Shift the registers and feed back the results
        new_state = [0] * 288

        # Register A: shift right and insert t3
        new_state[0] = t3
        new_state[1:93] = s[0:92]

        # Register B: shift right and insert t1
        new_state[93] = t1
        new_state[94:177] = s[93:176]

        # Register C: shift right and insert t2
        new_state[177] = t2
        new_state[178:288] = s[177:287]

        self.state = new_state

        return z

    # Generates a specified number of keystream bytes.
    def gen_bytes(self, n: int) -> bytes:
        out = bytearray()
        
        for _ in range(n):
            value = 0
            for bit_index in range(8):
                bit = self._gen_bit()
                value |= (bit & 1) << bit_index
            out.append(value)
            
        return bytes(out)


if __name__ == '__main__':
    # Load test vectors
    with open(JSON_PATH, "r", encoding="utf-8") as f:
        test_vectors = json.load(f)

    print("\n=== Task 1: Trivium ===")

    # Run tests over all vectors
    for tv in test_vectors:
        trivium = Trivium(bytes.fromhex(tv["key"]), bytes.fromhex(tv["iv"]))
        expected = bytes.fromhex(tv["stream"])
        
        # Check generated stream vs expected stream
        result = trivium.gen_bytes(32)
        passed = (result == expected)

        print(f"Test #{tv['number']}: {'PASS' if passed else 'FAIL'}")

        # Display debug info on failure
        if not passed:
            print(f"  Got CT: {result.hex()} (Expected: {expected.hex()})")
