# TASK 7: Surgical CBC-R Attack for Privilege Escalation
import time
import requests

BLOCK_SIZE = 20
URL = "https://interrato.dev/infosec/lab1"

# The original token and plaintext blocks
ORIGINAL_TOKEN_HEX = (
    "6ca1778f4e71cbf7bc3c1a9c8abff402e522f6d41b64fb7723a30de687da8ff20"
    "e0ba82920b6787e750b5a700b769be6701d7416d0d08439e596cc7c0af9ac76710"
    "b95c0423f4a993b709e0891e50e47f791db75da8ee648a0ab0a644317d979a76b27c0"
)
ORIGINAL_P1 = b'{"group":"ChaCha","p'
ORIGINAL_P2 = b'rivileged":false,"to'
DESIRED_P2  = b'rivileged":true ,"to'

session = requests.Session()

# Sends a modified ciphertext to the server and checks if the padding is valid.
def oracle(mask: bytes, target: bytes) -> bool:
    while True:
        response = session.get(f"{URL}?token={(mask + target).hex()}", timeout=10)
        # Handle rate limiting by waiting and retrying
        if response.status_code == 429:
            time.sleep(0.3)
            continue
        # 422 means padding is invalid
        return response.status_code != 422

# Recovers the intermediate state of a single ciphertext block using the padding oracle.
def recover_intermediate(target_block: bytes) -> bytes:
    intermediate = bytearray(BLOCK_SIZE)

    # Loop backwards through each byte of the block
    for position in range(BLOCK_SIZE - 1, -1, -1):
        # Prepare the mask: dummy bytes + zeros for the unknown part
        crafted_block = bytearray([0x41] * position + [0x00] * (BLOCK_SIZE - position))

        # Apply the already recovered intermediate bytes
        for index in range(position + 1, BLOCK_SIZE):
            crafted_block[index] = intermediate[index]

        # Try all 256 possible byte values
        for guess in range(256):
            crafted_block[position] = guess

            if not oracle(bytes(crafted_block), target_block):
                continue

            # If not at the first byte, avoid false positives
            if position > 0:
                crafted_block[position - 1] ^= 0xFF
                if not oracle(bytes(crafted_block), target_block):
                    crafted_block[position - 1] ^= 0xFF
                    continue
                crafted_block[position - 1] ^= 0xFF

            # Valid padding found, calculate the intermediate byte
            intermediate[position] = guess ^ 0x80
            print(f"  [+] Intermediate byte {position:02d} recovered", flush=True)
            break
        else:
            raise RuntimeError(f"Unable to recover intermediate byte at position {position}")

    return bytes(intermediate)

# Performs a surgical CBC-R attack to modify a specific block of plaintext.
def forge_token_surgically(original_token_hex: str) -> bytes:
    token = bytes.fromhex(original_token_hex)
    blocks = [token[i:i + BLOCK_SIZE] for i in range(0, len(token), BLOCK_SIZE)]

    original_c1 = blocks[1]

    print("[*] Starting surgical CBC-R privilege escalation")
    print("[*] Rewriting plaintext block 2: 'false' -> 'true '")

    # Modify C1 to change P2
    modified_c1 = bytes(
        original_c1[i] ^ ORIGINAL_P2[i] ^ DESIRED_P2[i]
        for i in range(BLOCK_SIZE)
    )

    print("[*] Recovering D_k(C1') via padding oracle...")
    intermediate_c1 = recover_intermediate(modified_c1)

    print("[*] Recomputing IV to preserve plaintext block 1")
    # Recompute IV to keep P1 unchanged
    modified_iv = bytes(
        intermediate_c1[i] ^ ORIGINAL_P1[i]
        for i in range(BLOCK_SIZE)
    )

    # Assemble the new token
    forged_token = modified_iv + modified_c1 + b"".join(blocks[2:])

    print("[+] Forged token successfully constructed")
    return forged_token

# Verifies the forged token against the server.
def verify_token(token: bytes) -> None:
    print("\n[*] Verifying forged token...")
    response = session.get(f"{URL}?token={token.hex()}", timeout=10)
    print(f"HTTP {response.status_code}: {response.text.strip()}")


if __name__ == "__main__":
    forged_token = forge_token_surgically(ORIGINAL_TOKEN_HEX)
    print(f"\n[+] Forged token (hex):\n{forged_token.hex()}")
    verify_token(forged_token)
