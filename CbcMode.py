# TASK 5: Implement the CBC mode of operation

from LubyRackOff import LubyRackoffCipher
import json

JSON_PATH = "vectors/lab1task5.json"

# Computes the XOR between two byte sequences of the same length.
def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("Inputs must have the same length")
    return bytes(x ^ y for x, y in zip(a, b))

# Splits a byte sequence into chunks of the given block size.
def split_blocks(data: bytes, block_size: int) -> list[bytes]:
    if len(data) % block_size != 0:
        raise ValueError("Data length must be a multiple of the block size")
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

# Applies ISO/IEC 7816-4 padding to the given data.
def iso_7816_4_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + b"\x80" + (b"\x00" * (pad_len - 1))

# Removes ISO/IEC 7816-4 padding from the decrypted data.
def iso_7816_4_unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")

    # Start from the end and remove zeros
    i = len(data) - 1
    while i >= 0 and data[i] == 0x00:
        i -= 1

    # Ensure the padding marker is correct
    if i < 0 or data[i] != 0x80:
        raise ValueError("Invalid ISO/IEC 7816-4 padding")

    return data[:i]

# Implements CBC mode encryption and decryption using the Luby-Rackoff cipher.
class CBCCipher:
    BLOCK_SIZE = 20

    # Initializes the CBC cipher using the Luby-Rackoff block cipher.
    def __init__(self, key: bytes):
        self.block_cipher = LubyRackoffCipher(key, rounds=4)

    # Encrypts the plaintext using CBC mode and returns IV + ciphertext.
    def encrypt(self, plaintext: bytes, iv: bytes) -> bytes:
        if len(iv) != self.BLOCK_SIZE:
            raise ValueError(f"IV must be {self.BLOCK_SIZE} bytes")

        # Apply padding and split into blocks
        padded = iso_7816_4_pad(plaintext, self.BLOCK_SIZE)
        blocks = split_blocks(padded, self.BLOCK_SIZE)

        previous = iv
        ciphertext_blocks = [iv]

        # CBC Encryption: XOR plaintext with previous ciphertext (or IV), then encrypt
        for block in blocks:
            xored = xor_bytes(block, previous)
            encrypted = self.block_cipher.encrypt(xored)
            ciphertext_blocks.append(encrypted)
            previous = encrypted

        return b"".join(ciphertext_blocks)

    # Decrypts a CBC mode ciphertext (which includes the IV) and removes padding.
    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) < 2 * self.BLOCK_SIZE:
            raise ValueError("Ciphertext is too short")

        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be a multiple of the block size")

        # Extract IV and ciphertext blocks
        blocks = split_blocks(ciphertext, self.BLOCK_SIZE)
        iv = blocks[0]
        cipher_blocks = blocks[1:]

        previous = iv
        plaintext_blocks = []

        # CBC Decryption: Decrypt ciphertext block, then XOR with previous ciphertext (or IV)
        for block in cipher_blocks:
            decrypted = self.block_cipher.decrypt(block)
            plain_block = xor_bytes(decrypted, previous)
            plaintext_blocks.append(plain_block)
            previous = block

        # Unpad the concatenated plaintext blocks
        padded_plaintext = b"".join(plaintext_blocks)
        return iso_7816_4_unpad(padded_plaintext, self.BLOCK_SIZE)


if __name__ == '__main__':
    # Load test vectors
    with open(JSON_PATH, "r", encoding="utf-8") as f:
        vectors = json.load(f)

    print("\n=== Task 5: CBC Mode ===")

    # Run tests over all vectors
    for tv in vectors:
        cipher = CBCCipher(bytes.fromhex(tv["key"]))
        iv = bytes.fromhex(tv["iv"])
        msg = bytes.fromhex(tv["msg"])
        expected_ct = bytes.fromhex(tv["ct"])

        # Test encryption
        result_ct = cipher.encrypt(msg, iv)
        enc_ok = (result_ct == expected_ct)

        # Test decryption
        try:
            result_msg = cipher.decrypt(expected_ct)
            dec_ok = (result_msg == msg)
        except Exception as e:
            dec_ok = False

        print(f"Test #{tv['number']}: ENC {'PASS' if enc_ok else 'FAIL'} | DEC {'PASS' if dec_ok else 'FAIL'}")

        # Display debug info on failure
        if not enc_ok:
            print(f"  ENC FAIL -> Got CT: {result_ct.hex()} (Expected: {expected_ct.hex()})")
        if not dec_ok:
            print("  DEC FAIL -> Decryption resulted in an error or mismatched message")
