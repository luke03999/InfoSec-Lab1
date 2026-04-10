#Task 6: Perform the padding decryption oracle attack

import time
import requests

BLOCK = 20
URL = "https://interrato.dev/infosec/lab1"
TOKEN = "6ca1778f4e71cbf7bc3c1a9c8abff402e522f6d41b64fb7723a30de687da8ff20e0ba82920b6787e750b5a700b769be6701d7416d0d08439e596cc7c0af9ac76710b95c0423f4a993b709e0891e50e47f791db75da8ee648a0ab0a644317d979a76b27c0"

session = requests.Session()


def oracle(mask: bytes, target: bytes) -> bool:
    while True:
        r = session.get(f"{URL}?token={(mask + target).hex()}", timeout=10)
        if r.status_code == 429:
            time.sleep(0.3)
            continue
        return r.status_code != 422


def attack_block(prev_block: bytes, target: bytes) -> bytes:
    inter = bytearray(BLOCK)

    for pos in range(BLOCK - 1, -1, -1):
        mask = bytearray([0x41] * pos + [0x00] * (BLOCK - pos))
        found = False

        for k in range(pos + 1, BLOCK):
            mask[k] = inter[k]

        for guess in range(256):
            mask[pos] = guess

            if not oracle(bytes(mask), target):
                continue

            if pos > 0:
                mask[pos - 1] ^= 0xFF
                if not oracle(bytes(mask), target):
                    mask[pos - 1] ^= 0xFF
                    continue
                mask[pos - 1] ^= 0xFF

            inter[pos] = guess ^ 0x80
            pt_byte = inter[pos] ^ prev_block[pos]
            printable = chr(pt_byte) if 32 <= pt_byte <= 126 else "."
            print(f"  [+] Byte {pos:02d} recovered: 0x{pt_byte:02x} ({printable})", flush=True)
            found = True
            break

        if not found:
            raise RuntimeError(f"Failed to recover byte at position {pos}")

    return bytes(inter)


def iso_7816_4_unpad(data: bytes) -> bytes:
    i = len(data) - 1

    while i >= 0 and data[i] == 0x00:
        i -= 1

    if i < 0 or data[i] != 0x80:
        raise ValueError("Invalid ISO/IEC 7816-4 padding")

    return data[:i]


def decrypt(token_hex: str) -> bytes:
    ct = bytes.fromhex(token_hex)
    blocks = [ct[i * BLOCK:(i + 1) * BLOCK] for i in range(len(ct) // BLOCK)]
    plaintext = b""

    for i in range(1, len(blocks)):
        print(f"\n[*] Decrypting Block {i}/{len(blocks) - 1}")
        inter = attack_block(blocks[i - 1], blocks[i])

        pt = bytes(inter[j] ^ blocks[i - 1][j] for j in range(BLOCK))
        plaintext += pt

        printable_block = "".join(chr(b) if 32 <= b <= 126 else "." for b in pt)
        print(f"[+] Block {i} plaintext (hex): {pt.hex()}")
        print(f"[+] Block {i} plaintext (txt): {printable_block}")

    return iso_7816_4_unpad(plaintext)


if __name__ == "__main__":
    result = decrypt(TOKEN)
    print(f"\n[+] Final plaintext (hex): {result.hex()}")
    print(f"[+] Final plaintext: {result.decode()}")