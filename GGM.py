# TASK 2: Implement the GGM PRF
import json

from Trivium import Trivium
from utility import bytes_to_bits_msb

JSON_PATH = "vectors/lab1task2.json"

# Computes the Goldreich-Goldwasser-Micali (GGM) Pseudo-Random Function.
def ggm_prf(key: bytes, input_data: bytes) -> bytes:
    # Initial state is the given key
    s = key
    
    # Extract MSB bits from input
    bits = bytes_to_bits_msb(input_data)

    # Traverse the GGM tree bit by bit
    for bit in bits:
        # Generate 20 pseudo-random bytes using Trivium
        trivium = Trivium(s, b"\x00" * 10)
        out = trivium.gen_bytes(20)

        # Split output in left and right halves
        left = out[:10]
        right = out[10:]

        # Choose branch based on current input bit
        s = left if bit == 0 else right

    return s


if __name__ == '__main__':
    # Load test vectors
    with open(JSON_PATH, "r", encoding="utf-8") as f:
        test_vectors = json.load(f)

    print("\nTask 2: GGM PRF")

    # Run tests over all vectors
    for tv in test_vectors:
        key = bytes.fromhex(tv["key"])
        input_data = bytes.fromhex(tv["in"])
        expected = bytes.fromhex(tv["out"])

        # Execute PRF and compare with expected output
        result = ggm_prf(key, input_data)
        passed = (result == expected)

        print(f"Test #{tv['number']}: {'PASS' if passed else 'FAIL'}")

        # Provide debug info only if test fails
        if not passed:
            print(f"  Got CT: {result.hex()} (Expected: {expected.hex()})")
