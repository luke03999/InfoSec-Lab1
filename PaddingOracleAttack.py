# TASK 6: Padding Oracle Attack

import time
import requests

BLOCK  = 20
URL    = "https://interrato.dev/infosec/lab1"
TOKEN  = "6ca1778f4e71cbf7bc3c1a9c8abff402e522f6d41b64fb7723a30de687da8ff20e0ba82920b6787e750b5a700b769be6701d7416d0d08439e596cc7c0af9ac76710b95c0423f4a993b709e0891e50e47f791db75da8ee648a0ab0a644317d979a76b27c0"

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

# Recovers the intermediate state of a single ciphertext block.
# Works backwards, byte by byte, from the end of the block.
def attack_block(target: bytes) -> bytes:
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
            pt_byte = inter[pos] ^ target[pos]  # preview of the plaintext byte
            print(f"  byte [{pos:2d}] = 0x{pt_byte:02x}", flush=True)
            break
            
    return bytes(inter)

# Removes trailing zero padding from the decrypted data.
def unpad(data: bytes) -> bytes:
    i = len(data) - 1
    while data[i] == 0x00:
        i -= 1
    return data[:i]

# Splits the token into blocks and decrypts them one by one.
def decrypt(token_hex: str) -> bytes:
    ct = bytes.fromhex(token_hex)
    blocks = [ct[i*BLOCK:(i+1)*BLOCK] for i in range(len(ct) // BLOCK)]
    plaintext = b""
    
    # Decrypt starting from the second block, using the previous block as IV
    for i in range(1, len(blocks)):
        print(f"\n[block {i}/{len(blocks)-1}]")
        inter = attack_block(blocks[i])
        
        # XOR intermediate state with the previous block to get the plaintext
        pt = bytes(inter[j] ^ blocks[i-1][j] for j in range(BLOCK))
        plaintext += pt
        print(f"block {i}: {pt.hex()}")
        
    return unpad(plaintext)

if __name__ == "__main__":
    result = decrypt(TOKEN)
    print(f"\nplaintext: {result.decode()}")