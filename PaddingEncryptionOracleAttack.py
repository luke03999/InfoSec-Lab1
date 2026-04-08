# Task 7: Padding Encryption Oracle Attack

import os
import time
import requests

BLOCK = 20
URL   = "https://interrato.dev/infosec/lab1"

# The crafted plaintext containing privileged access to be encrypted from task 6
TARGET_PLAIN = b'{"group":"ChaCha","privileged":true,"token-id":"a8e144d231a0a23f"}'

session = requests.Session()

# Sends a modified ciphertext to the server and checks if the padding is valid.
# Returns True if no padding error (status code 422) occurs.
def oracle(mask: bytes, target: bytes) -> bool:
    while True:
        r = session.get(f"{URL}?token={(mask + target).hex()}", timeout=10)
        # Handle rate limiting by waiting and retrying
        if r.status_code == 429:
            time.sleep(0.3)
            continue
        # 422 means padding is invalid
        return r.status_code != 422

# Applies block padding to the given data.
def pad(data: bytes) -> bytes:
    pad_len = BLOCK - (len(data) % BLOCK)
    if pad_len == 0:
        pad_len = BLOCK
    return data + b"\x80" + b"\x00" * (pad_len - 1)

# Recovers the intermediate state of a single ciphertext block using the padding oracle.
# Works backwards, byte by byte, from the end of the block.
def get_intermediate(target: bytes) -> bytes:
    inter = bytearray(BLOCK)
    
    # Loop backwards through each byte of the block
    for pos in range(BLOCK - 1, -1, -1):
        # Prepare the mask: dummy bytes + zeros for the unknown part
        mask = bytearray([0x41] * pos + [0] * (BLOCK - pos))
        
        # Apply the already recovered intermediate bytes
        for k in range(pos + 1, BLOCK):
            mask[k] = inter[k]
            
        # Try all 256 possible byte values
        for guess in range(256):
            mask[pos] = guess
            if not oracle(bytes(mask), target):
                continue
                
            # If we are not at the first byte, avoid false positives
            if pos > 0:
                mask[pos - 1] ^= 0xFF
                if not oracle(bytes(mask), target):
                    mask[pos - 1] ^= 0xFF
                    continue
                mask[pos - 1] ^= 0xFF
                
            # Valid padding found, calculate the intermediate byte
            inter[pos] = guess ^ 0x80
            print(f"  byte [{pos:2d}] found", flush=True)
            break
            
    return bytes(inter)

# Forges a valid ciphertext for a given plaintext by working backward.
# Starts from a random last block and builds previous blocks using the intermediate state.
def encrypt(plaintext: bytes) -> bytes:
    padded = pad(plaintext)
    blocks = [padded[i*BLOCK:(i+1)*BLOCK] for i in range(len(padded) // BLOCK)]
    n = len(blocks)

    cipher_blocks = [None] * (n + 1)
    
    # Start with a random block as the last block of the forged ciphertext
    cipher_blocks[n] = os.urandom(BLOCK)

    # Work backwards to calculate the previous ciphertext block
    for i in range(n, 0, -1):
        print(f"\n[encrypting block {n - i + 1}/{n}] recovering D_k(C_{i})...")
        
        # Find the intermediate state of the current block
        inter = get_intermediate(cipher_blocks[i])
        
        # The previous block must XOR with the intermediate state to produce the desired plaintext block
        cipher_blocks[i - 1] = bytes(inter[j] ^ blocks[i - 1][j] for j in range(BLOCK))

    return b"".join(cipher_blocks)

if __name__ == "__main__":
    print(f"Target plaintext: {TARGET_PLAIN.decode()}\n")

    token = encrypt(TARGET_PLAIN)
    print(f"\nForged token (hex): {token.hex()}")

    # Send the forged token to the server to verify it
    print("\nVerifying forged token...")
    r = session.get(f"{URL}?token={token.hex()}", timeout=10)
    print(f"HTTP {r.status_code}: {r.text.strip()}")

    # Interpret the server response
    if r.status_code == 200:
        print("\nAccess granted!")
    elif r.status_code == 403:
        print("\nToken valid but access forbidden (privileged=true may need server-side check).")
    else:
        print("\nSomething went wrong.")