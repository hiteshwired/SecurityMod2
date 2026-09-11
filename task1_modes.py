"""
Task 1: Modes of Operation (ECB and CBC)
CSC-3201: Introduction to Computer Security

This module implements AES-128 block cipher modes of operation (ECB and CBC)
from scratch using only the single-block AES-128 primitive. It also includes
PKCS#7 padding, key/IV generation, and BMP image encryption utilities.
"""

import os
from Crypto.Cipher import AES

# AES block size in bytes (128 bits = 16 bytes)
BLOCK_SIZE = 16


def generate_key(key_size: int = BLOCK_SIZE) -> bytes:
    """
    Generate a cryptographically secure random key.
    Default size is 16 bytes (128 bits) for AES-128.
    """
    return os.urandom(key_size)


def generate_iv(block_size: int = BLOCK_SIZE) -> bytes:
    """
    Generate a cryptographically secure random Initialization Vector (IV).
    """
    return os.urandom(block_size)


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Applies PKCS#7 padding to the input data so its length is a multiple of block_size.
    If the data is already a multiple of block_size, a full block of padding is added.
    """
    pad_len = block_size - (len(data) % block_size)
    padding = bytes([pad_len] * pad_len)
    return data + padding


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Removes and validates PKCS#7 padding from decrypted data.
    Raises ValueError if padding is invalid.
    """
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid data length for PKCS#7 unpadding.")
    
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding value.")
    
    # Check that all padding bytes match pad_len
    expected_padding = bytes([pad_len] * pad_len)
    if data[-pad_len:] != expected_padding:
        raise ValueError("Corrupted PKCS#7 padding.")
    
    return data[:-pad_len]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    Helper function to XOR two byte sequences of equal length.
    """
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt data using Electronic Codebook (ECB) mode.
    Encrypts exactly one 16-byte block at a time using the AES primitive.
    """
    # Create AES primitive instance for single-block encryption
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Apply PKCS#7 padding
    padded_data = pkcs7_pad(plaintext, BLOCK_SIZE)
    ciphertext = bytearray()
    
    # Process each 16-byte block independently
    for i in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[i:i + BLOCK_SIZE]
        encrypted_block = cipher.encrypt(block)
        ciphertext.extend(encrypted_block)
        
    return bytes(ciphertext)


def decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt data using Electronic Codebook (ECB) mode.
    Decrypts one 16-byte block at a time and removes PKCS#7 padding.
    """
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be a multiple of block size.")
        
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded = bytearray()
    
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        decrypted_block = cipher.decrypt(block)
        decrypted_padded.extend(decrypted_block)
        
    return pkcs7_unpad(bytes(decrypted_padded), BLOCK_SIZE)


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypt data using Cipher Block Chaining (CBC) mode.
    XORs each plaintext block with the previous ciphertext block (or IV for block 0)
    before encrypting with the AES-128 primitive.
    """
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV must be exactly {BLOCK_SIZE} bytes.")
        
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pkcs7_pad(plaintext, BLOCK_SIZE)
    
    ciphertext = bytearray()
    previous_block = iv
    
    for i in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[i:i + BLOCK_SIZE]
        # XOR with previous ciphertext block (or IV for first block)
        xored_block = xor_bytes(block, previous_block)
        # Encrypt the XORed block with AES primitive
        encrypted_block = cipher.encrypt(xored_block)
        
        ciphertext.extend(encrypted_block)
        # Current encrypted block becomes the feedback for the next iteration
        previous_block = encrypted_block
        
    return bytes(ciphertext)


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt data using Cipher Block Chaining (CBC) mode.
    Decrypts each block with AES primitive and XORs with the previous ciphertext block (or IV).
    """
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be a multiple of block size.")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV must be exactly {BLOCK_SIZE} bytes.")
        
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded = bytearray()
    previous_block = iv
    
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        current_block = ciphertext[i:i + BLOCK_SIZE]
        # Decrypt block with AES primitive
        decrypted_intermediate = cipher.decrypt(current_block)
        # XOR with previous ciphertext block (or IV for first block)
        plaintext_block = xor_bytes(decrypted_intermediate, previous_block)
        
        decrypted_padded.extend(plaintext_block)
        previous_block = current_block
        
    return pkcs7_unpad(bytes(decrypted_padded), BLOCK_SIZE)


def encrypt_file_ecb(input_path: str, output_path: str, key: bytes | None = None) -> bytes:
    """
    Encrypt an arbitrary plaintext file using ECB mode and save to output_path.
    Returns the key used.
    """
    if key is None:
        key = generate_key()
        
    with open(input_path, "rb") as f:
        data = f.read()
        
    encrypted_data = encrypt_ecb(data, key)
    
    with open(output_path, "wb") as f:
        f.write(encrypted_data)
        
    return key


def encrypt_file_cbc(input_path: str, output_path: str, key: bytes | None = None, iv: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Encrypt an arbitrary plaintext file using CBC mode and save to output_path.
    Returns the (key, iv) used.
    """
    if key is None:
        key = generate_key()
    if iv is None:
        iv = generate_iv()
        
    with open(input_path, "rb") as f:
        data = f.read()
        
    encrypted_data = encrypt_cbc(data, key, iv)
    
    with open(output_path, "wb") as f:
        f.write(encrypted_data)
        
    return key, iv


def encrypt_bmp_ecb(input_bmp_path: str, output_bmp_path: str, key: bytes | None = None, header_size: int = 54) -> bytes:
    """
    Encrypt a BMP file using ECB mode while preserving the unencrypted BMP header.
    This allows the encrypted BMP to still be opened as a valid image file to visualize
    the patterns that ECB mode fails to conceal.
    """
    if key is None:
        key = generate_key()
        
    with open(input_bmp_path, "rb") as f:
        bmp_data = f.read()
        
    header = bmp_data[:header_size]
    pixel_data = bmp_data[header_size:]
    
    encrypted_pixels = encrypt_ecb(pixel_data, key)
    
    with open(output_bmp_path, "wb") as f:
        f.write(header + encrypted_pixels)
        
    return key


def encrypt_bmp_cbc(input_bmp_path: str, output_bmp_path: str, key: bytes | None = None, iv: bytes | None = None, header_size: int = 54) -> tuple[bytes, bytes]:
    """
    Encrypt a BMP file using CBC mode while preserving the unencrypted BMP header.
    Shows the pseudorandom noise diffusion achieved by CBC mode.
    """
    if key is None:
        key = generate_key()
    if iv is None:
        iv = generate_iv()
        
    with open(input_bmp_path, "rb") as f:
        bmp_data = f.read()
        
    header = bmp_data[:header_size]
    pixel_data = bmp_data[header_size:]
    
    encrypted_pixels = encrypt_cbc(pixel_data, key, iv)
    
    with open(output_bmp_path, "wb") as f:
        f.write(header + encrypted_pixels)
        
    return key, iv


if __name__ == "__main__":
    print("Testing Task 1 Implementations...")
    test_key = generate_key()
    test_iv = generate_iv()
    test_msg = b"Computer Security Lab - Testing AES-128 manual ECB and CBC implementation!"
    
    # Test ECB
    ecb_cipher = encrypt_ecb(test_msg, test_key)
    ecb_decrypted = decrypt_ecb(ecb_cipher, test_key)
    assert ecb_decrypted == test_msg, "ECB Decryption Failed!"
    print("[PASS] ECB Encryption & Decryption verified.")
    
    # Test CBC
    cbc_cipher = encrypt_cbc(test_msg, test_key, test_iv)
    cbc_decrypted = decrypt_cbc(cbc_cipher, test_key, test_iv)
    assert cbc_decrypted == test_msg, "CBC Decryption Failed!"
    print("[PASS] CBC Encryption & Decryption verified.")
