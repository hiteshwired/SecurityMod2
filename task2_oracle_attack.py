"""
Task 2: Limits of Confidentiality & CBC Bit-Flipping Attack
CSC-3201: Introduction to Computer Security

This module implements a simulated authentication oracle server using AES-128-CBC
and demonstrates how CBC malleability allows an attacker to alter plaintext without
knowing the secret key (CBC bit-flipping attack).
"""

from task1_modes import encrypt_cbc, decrypt_cbc, generate_key, generate_iv

# Server-side persistent key and IV (initialized once for the session)
SERVER_KEY = generate_key()
SERVER_IV = generate_iv()


def url_encode_special_chars(s: str) -> str:
    """
    URL encodes only ';' and '=' characters in the user input string.
    ';' -> '%3B', '=' -> '%3D'
    """
    # Replace ';' and '=' with their percent-encoded equivalents
    encoded = s.replace(";", "%3B").replace("=", "%3D")
    return encoded


def submit(user_input: str) -> bytes:
    """
    Oracle Submission Function (Server-side):
    1. URL-encodes ';' and '=' characters in user_input.
    2. Prepends 'userid=456;userdata=' and appends ';session-id=31337'.
    3. Pads the resulting string using PKCS#7 and encrypts with AES-128-CBC.
    Returns the ciphertext.
    """
    # Step 1: URL encode forbidden delimiter characters
    sanitized_input = url_encode_special_chars(user_input)
    
    # Step 2: Prepend prefix and append suffix
    prefix = "userid=456;userdata="
    suffix = ";session-id=31337"
    full_string = prefix + sanitized_input + suffix
    
    # Step 3: Pad and encrypt using AES-128-CBC
    plaintext_bytes = full_string.encode("utf-8")
    ciphertext = encrypt_cbc(plaintext_bytes, SERVER_KEY, SERVER_IV)
    
    return ciphertext


def verify(ciphertext: bytes) -> bool:
    """
    Oracle Verification Function (Server-side):
    1. Decrypts the ciphertext using AES-128-CBC.
    2. Unpads the plaintext (handling padding exceptions gracefully).
    3. Checks if ';admin=true;' exists in the resulting string.
    Returns True if ';admin=true;' is found, False otherwise.
    """
    try:
        # Decrypt using the persistent server key and IV
        decrypted_bytes = decrypt_cbc(ciphertext, SERVER_KEY, SERVER_IV)
        # Decode to string using 'latin1' or 'utf-8' with replacement to avoid decode crashes on scrambled blocks
        decrypted_str = decrypted_bytes.decode("latin1")
        
        # Check if the target admin string is present
        return ";admin=true;" in decrypted_str
    except (ValueError, KeyError, UnicodeDecodeError):
        # If decryption or padding fails, authentication fails
        return False


def cbc_bit_flip_attack() -> tuple[bytes, bytes, bool]:
    """
    Executes the CBC Bit-Flipping Attack:
    
    Goal: Modify ciphertext returned by submit() so that verify() returns True,
    even though submit() URL-encodes ';' and '=' to prevent admin injection.
    
    Mechanism:
    In CBC mode: P_i = D_K(C_i) XOR C_{i-1}
    Flipping bits in ciphertext block C_{i-1} flips the exact same bits in plaintext P_i.
    
    Structure:
    Prefix: 'userid=456;userdata=' (20 bytes)
    Block 0 (0..15):  'userid=456;userd' (16 bytes)
    Block 1 (16..31): 'ata=' + 12 filler bytes (16 bytes)
    Block 2 (32..47): ':admin<true:' (12 bytes) + padding/suffix
    
    By modifying ciphertext in Block 1 at offsets 0, 6, and 11:
    - Block 1 C_1[0]  XOR (':' XOR ';') -> turns ':' into ';' in P_2[0]
    - Block 1 C_1[6]  XOR ('<' XOR '=') -> turns '<' into '=' in P_2[6]
    - Block 1 C_1[11] XOR (':' XOR ';') -> turns ':' into ';' in P_2[11]
    """
    # 12 filler bytes to align our payload right at the start of Block 2 (index 32)
    filler = "A" * 12
    # Replacement string where ':' differs by 1 bit from ';', and '<' differs by 1 bit from '='
    # ':' (0x3A) ^ 0x01 = ';' (0x3B)
    # '<' (0x3C) ^ 0x01 = '=' (0x3D)
    target_payload = ":admin<true:"
    user_input = filler + target_payload
    
    # 1. Normal submission
    orig_ciphertext = submit(user_input)
    
    # Verify that normal submission cannot produce admin access
    initial_verify = verify(orig_ciphertext)
    print(f"Initial verify() with user input: {initial_verify} (should be False)")
    
    # 2. Modify ciphertext
    # Convert ciphertext to mutable bytearray
    modified_ct = bytearray(orig_ciphertext)
    
    # Block 1 starts at index 16 (bytes 16..31).
    # Since payload starts at Block 2 index 32:
    # Offset 0 in Block 2 corresponds to offset 16 in ciphertext (Block 1 index 0)
    # Offset 6 in Block 2 corresponds to offset 16 + 6 = 22 in ciphertext (Block 1 index 6)
    # Offset 11 in Block 2 corresponds to offset 16 + 11 = 27 in ciphertext (Block 1 index 11)
    
    block1_start = 16
    
    # Bit flip for first ':' -> ';'
    modified_ct[block1_start + 0] ^= (ord(':') ^ ord(';'))
    # Bit flip for '<' -> '='
    modified_ct[block1_start + 6] ^= (ord('<') ^ ord('='))
    # Bit flip for second ':' -> ';'
    modified_ct[block1_start + 11] ^= (ord(':') ^ ord(';'))
    
    result_ciphertext = bytes(modified_ct)
    
    # 3. Test verification with modified ciphertext
    attack_success = verify(result_ciphertext)
    print(f"Modified ciphertext verify() result: {attack_success} (should be True!)")
    
    return orig_ciphertext, result_ciphertext, attack_success


if __name__ == "__main__":
    print("--- Task 2: Authentication Oracle & CBC Bit-Flipping Demo ---")
    
    # Test safe submission
    safe_input = "You're the man now, dog"
    ct_safe = submit(safe_input)
    print(f"Submitted: {safe_input}")
    print(f"Verify result: {verify(ct_safe)}")
    
    # Test direct injection attempt (blocked by URL encoding)
    injection_input = ";admin=true;"
    ct_injection = submit(injection_input)
    print(f"\nAttempted direct injection: {injection_input}")
    print(f"Verify result: {verify(ct_injection)} (blocked by URL encoding)")
    
    # Run CBC Bit-flipping attack
    print("\nExecuting CBC Bit-Flipping Attack...")
    _, _, success = cbc_bit_flip_attack()
    if success:
        print("[SUCCESS] Bit-flipping attack bypassed authentication!")
    else:
        print("[FAILED] Bit-flipping attack failed.")
