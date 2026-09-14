from task1_modes import decrypt_cbc, encrypt_cbc, generate_iv, generate_key

# server picks key/IV once and reuses for the whole run
SERVER_KEY = generate_key()
SERVER_IV = generate_iv()


def url_encode_special_chars(s: str) -> str:
    # only care about blocking ';' and '=' from user input
    return s.replace(";", "%3B").replace("=", "%3D")


def submit(user_input: str) -> bytes:
    # userid=456;userdata=<sanitized input>;session-id=31337, encrypted with CBC
    sanitized = url_encode_special_chars(user_input)
    full_string = "userid=456;userdata=" + sanitized + ";session-id=31337"
    return encrypt_cbc(full_string.encode("utf-8"), SERVER_KEY, SERVER_IV)


def verify(ciphertext: bytes) -> bool:
    decrypted = decrypt_cbc(ciphertext, SERVER_KEY, SERVER_IV)
    # latin1 so tampered bytes don't cause a decode crash
    text = decrypted.decode("latin1")
    return ";admin=true;" in text


def cbc_bit_flip_attack() -> tuple[bytes, bytes, bool]:
    # P_i = D(C_i) XOR C_(i-1), so flipping a bit in C_(i-1) flips the same
    # bit in P_i. Byte layout:
    #   Block 0 (0-15):  "userid=456;userd"
    #   Block 1 (16-31): "ata=" + 12 filler bytes
    #   Block 2 (32-47): our payload
    # submit 12 filler bytes + ":admin<true:" so the payload lands in block 2,
    # then flip 3 bytes in block 1 to turn ":admin<true:" into ";admin=true;"
    filler = "A" * 12
    payload = ":admin<true:"  # one bit off from ';' and '=' on purpose
    ciphertext = submit(filler + payload)

    modified = bytearray(ciphertext)
    block1_start = 16

    # ':' 0x3A vs ';' 0x3B, '<' 0x3C vs '=' 0x3D - one bit apart each
    modified[block1_start + 0] ^= ord(":") ^ ord(";")
    modified[block1_start + 6] ^= ord("<") ^ ord("=")
    modified[block1_start + 11] ^= ord(":") ^ ord(";")

    tampered_ciphertext = bytes(modified)
    return ciphertext, tampered_ciphertext, verify(tampered_ciphertext)


if __name__ == "__main__":
    print("Task 2 - Authentication Oracle & CBC Bit-Flipping Attack")
    print("-" * 55)

    safe_input = "You're the man now, dog"
    print(f"submit('{safe_input}') -> verify() = {verify(submit(safe_input))}")

    injection = ";admin=true;"
    print(f"submit('{injection}') -> verify() = {verify(submit(injection))}  (blocked by URL-encoding)")

    print("\nRunning the bit-flipping attack...")
    _, tampered_ct, success = cbc_bit_flip_attack()
    print(f"verify(tampered ciphertext) = {success}")
    print("[SUCCESS] got admin access without the key!" if success else "[FAILED] attack didn't work")
