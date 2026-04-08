def bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("The bits length must be a multiple of 8")

    result = bytearray()

    for i in range(0, len(bits), 8):
        value = 0
        for bit_index in range(8):
            bit = bits[i + bit_index]
            value = value | (bit << bit_index)
        result.append(value)

    return bytes(result)


def bytes_to_bits_msb(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits