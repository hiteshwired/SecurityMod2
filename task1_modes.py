import os
from Crypto.Cipher import AES

BLOCK_SIZE = 16  # AES block size in bytes


def generate_key(key_size: int = BLOCK_SIZE) -> bytes:
    return os.urandom(key_size)


def generate_iv(block_size: int = BLOCK_SIZE) -> bytes:
    return os.urandom(block_size)


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    # pad with pad_len copies of the byte pad_len, even if already aligned
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ECB mode

def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    # no chaining -> same plaintext block always gives same ciphertext block
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)

    ciphertext = bytearray()
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        ciphertext += cipher.encrypt(block)

    return bytes(ciphertext)


def decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        padded_plaintext += cipher.decrypt(block)

    return pkcs7_unpad(bytes(padded_plaintext), BLOCK_SIZE)


# CBC mode

def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    # C0 = E(P0 XOR IV), Ci = E(Pi XOR C(i-1)) - chaining is what stops the ECB pattern leak
    cipher = AES.new(key, AES.MODE_ECB)  # still one block at a time under the hood
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)

    ciphertext = bytearray()
    prev_block = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        enc_block = cipher.encrypt(xor_bytes(block, prev_block))
        ciphertext += enc_block
        prev_block = enc_block

    return bytes(ciphertext)


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = bytearray()
    prev_block = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        padded_plaintext += xor_bytes(cipher.decrypt(block), prev_block)
        prev_block = block  # previous ciphertext block, not the decrypted one

    return pkcs7_unpad(bytes(padded_plaintext), BLOCK_SIZE)


# file / image helpers

def encrypt_file_ecb(input_path: str, output_path: str, key: bytes | None = None) -> bytes:
    if key is None:
        key = generate_key()

    with open(input_path, "rb") as f:
        data = f.read()

    with open(output_path, "wb") as f:
        f.write(encrypt_ecb(data, key))

    return key


def encrypt_file_cbc(
    input_path: str, output_path: str, key: bytes | None = None, iv: bytes | None = None
) -> tuple[bytes, bytes]:
    if key is None:
        key = generate_key()
    if iv is None:
        iv = generate_iv()

    with open(input_path, "rb") as f:
        data = f.read()

    with open(output_path, "wb") as f:
        f.write(encrypt_cbc(data, key, iv))

    return key, iv


def encrypt_bmp_ecb(
    input_bmp_path: str, output_bmp_path: str, key: bytes | None = None, header_size: int = 54
) -> bytes:
    # leave the header alone so it still opens as a valid image
    if key is None:
        key = generate_key()

    with open(input_bmp_path, "rb") as f:
        bmp_data = f.read()

    header, pixels = bmp_data[:header_size], bmp_data[header_size:]
    encrypted_pixels = encrypt_ecb(pixels, key)

    with open(output_bmp_path, "wb") as f:
        f.write(header + encrypted_pixels)

    return key


def encrypt_bmp_cbc(
    input_bmp_path: str,
    output_bmp_path: str,
    key: bytes | None = None,
    iv: bytes | None = None,
    header_size: int = 54,
) -> tuple[bytes, bytes]:
    if key is None:
        key = generate_key()
    if iv is None:
        iv = generate_iv()

    with open(input_bmp_path, "rb") as f:
        bmp_data = f.read()

    header, pixels = bmp_data[:header_size], bmp_data[header_size:]
    encrypted_pixels = encrypt_cbc(pixels, key, iv)

    with open(output_bmp_path, "wb") as f:
        f.write(header + encrypted_pixels)

    return key, iv


if __name__ == "__main__":
    print("Running Task 1 self-test...")

    key = generate_key()
    iv = generate_iv()
    msg = b"Computer Security Lab - testing the ECB and CBC implementations!"

    assert decrypt_ecb(encrypt_ecb(msg, key), key) == msg, "ECB round-trip failed"
    print("  ECB round-trip ok")

    assert decrypt_cbc(encrypt_cbc(msg, key, iv), key, iv) == msg, "CBC round-trip failed"
    print("  CBC round-trip ok")
