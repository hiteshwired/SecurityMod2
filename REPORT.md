# CSC-3201: Introduction to Computer Security
## Lab Assignment: Symmetric Key Cryptography Exploration
**Author:** Student  
**Course:** CSC-3201 Computer Security  
**Date:** September 2026  

---

### Executive Summary

In this lab, we explored symmetric key cryptography, block cipher modes of operation, the cryptographic limits of confidentiality without integrity, and empirical performance differences between symmetric (AES) and asymmetric (RSA) algorithms.

1. **Task 1: Modes of Operation (ECB vs. CBC)**: We implemented custom Electronic Codebook (ECB) and Cipher Block Chaining (CBC) modes from scratch using only the single-block AES-128 primitive and custom PKCS#7 padding. We evaluated both modes on bitmap (BMP) images by encrypting the pixel payload while preserving the 54-byte BMP header.
2. **Task 2: Limits of Confidentiality (CBC Bit-Flipping Attack)**: We built a simulated authentication oracle server (`submit()` and `verify()`) using AES-128-CBC. We then demonstrated how CBC's mathematical malleability enables an attacker to modify specific bits in ciphertext blocks to achieve privilege escalation (injecting `;admin=true;`), completely bypassing application-level URL input sanitization without knowing the encryption key.
3. **Task 3: Performance Comparison (AES vs. RSA)**: Using OpenSSL benchmark utilities, we benchmarked symmetric (AES-128, AES-192, AES-256) and asymmetric (RSA-512, 1024, 2048, 4096) algorithms across varying block and key sizes, generating comparative performance curves.

---

### Task 1: Modes of Operation Implementation & Analysis

#### 1. Implementation Details
The AES-128 cipher operates strictly on 128-bit (16-byte) blocks. To encrypt arbitrary-length data, block ciphers require a *mode of operation* and a padding scheme:
- **PKCS#7 Padding**: For data with length $L$, the number of pad bytes $P$ is calculated as:
  $$P = 16 - (L \pmod{16})$$
  Each added byte has the integer value $P$. If $L$ is already a multiple of 16, a full 16-byte block of value `0x10` is appended.
- **Electronic Codebook (ECB) Mode**:
  Each 16-byte plaintext block $P_i$ is encrypted independently:
  $$C_i = E_K(P_i)$$
- **Cipher Block Chaining (CBC) Mode**:
  Each plaintext block $P_i$ is XORed with the previous ciphertext block $C_{i-1}$ (or Initialization Vector $IV$ for $i=0$) before block cipher encryption:
  $$C_0 = E_K(P_0 \oplus IV), \quad C_i = E_K(P_i \oplus C_{i-1}) \quad (\text{for } i \ge 1)$$
  Decryption is performed as:
  $$P_0 = D_K(C_0) \oplus IV, \quad P_i = D_K(C_i) \oplus C_{i-1} \quad (\text{for } i \ge 1)$$

#### 2. BMP Image Header Preservation
A standard Windows 24-bit uncompressed BMP file consists of:
1. **Bitmap File Header** (14 bytes): Contains the `'BM'` magic number and pixel data offset (54 bytes).
2. **DIB Header / BITMAPINFOHEADER** (40 bytes): Specifies image dimensions, bit depth (24 bpp), and compression format.
3. **Pixel Array** (Remaining bytes): Raw BGR pixel values.

By preserving the 54-byte header in plaintext and only encrypting the pixel array, image viewers can parse and render the ciphertext payload as an image.

#### 3. Visual Comparison & Question 1 Analysis

```
+---------------------------+---------------------------+---------------------------+
|     Original Image        |       ECB Encrypted       |       CBC Encrypted       |
| (High Contrast Shapes)    |    (Patterns Leaked!)     |   (Pseudorandom Noise)    |
+---------------------------+---------------------------+---------------------------+
```
*(Rendered side-by-side in `bmp_comparison.png`)*

##### Question 1 Answers:
- **Observations & Information Derived**:
  - In the **ECB-encrypted image**, the overall structure, outlines, shapes, and boundaries of the original image are still clearly visible to the human eye. We can easily derive the shape, positioning, and color uniformity of the underlying objects.
  - In the **CBC-encrypted image**, the output is visually indistinguishable from uniform pseudorandom static noise. No outlines, shapes, or structural information can be deduced.
- **Root Cause**:
  - **ECB Mode Determinism**: Because ECB encrypts each block $P_i$ independently under the same key $K$, any two identical 16-byte plaintext blocks $P_a = P_b$ always produce the exact same ciphertext block $C_a = C_b$. In images, large homogeneous regions (e.g., solid background, solid fills) consist of repeated sequences of identical pixel bytes. These repeated blocks produce identical ciphertext pixel patterns, completely preserving spatial redundancy and structural outlines.
  - **CBC Mode Diffusion**: CBC introduces dependency on previous ciphertext blocks via XOR chaining ($P_i \oplus C_{i-1}$) initialized by a random IV. Even if several plaintext blocks are identical ($P_a = P_b$), their XOR inputs differ because the preceding ciphertext blocks ($C_{a-1} \ne C_{b-1}$) differ. This achieves diffusion and semantic security (IND-CPA), ensuring identical plaintext blocks produce distinct, randomized ciphertext blocks.

---

### Task 2: Limits of Confidentiality & CBC Bit-Flipping Attack

#### 1. System Architecture & Oracle Specification
The simulated authentication service consists of two oracle functions sharing a static server key $K$ and $IV$:
- `submit(user_input)`:
  - Sanitizes `user_input` by percent-encoding `;` (`%3B`) and `=` (`%3D`).
  - Constructs payload: `userid=456;userdata=<sanitized_input>;session-id=31337`.
  - Applies PKCS#7 padding and encrypts with AES-128-CBC.
- `verify(ciphertext)`:
  - Decrypts using AES-128-CBC and unpads.
  - Searches for substring `;admin=true;`. Returns `True` if present, else `False`.

Because `submit()` sanitizes `;` and `=`, a direct input like `;admin=true;` becomes `%3Badmin%3Dtrue%3B`, making normal user injection impossible.

#### 2. CBC Bit-Flipping Attack Mechanism
CBC decryption for block $i$ is defined by:
$$P_i = D_K(C_i) \oplus C_{i-1}$$

For byte index $j$ within block $i$:
$$P_i[j] = D_K(C_i)[j] \oplus C_{i-1}[j]$$

If an attacker modifies byte $C_{i-1}[j]$ by XORing with an offset $\Delta$:
$$C'_{i-1}[j] = C_{i-1}[j] \oplus \Delta$$

During decryption of block $i$:
$$P'_i[j] = D_K(C_i)[j] \oplus C'_{i-1}[j] = D_K(C_i)[j] \oplus C_{i-1}[j] \oplus \Delta = P_i[j] \oplus \Delta$$

This yields an exact, controlled bit modification in plaintext block $P_i$ at index $j$.

#### 3. Attack Execution & Byte Alignment
- **Prefix**: `"userid=456;userdata="` (20 bytes).
  - **Block 0 (bytes 0–15)**: `"userid=456;userd"`
  - **Block 1 (bytes 16–31)**: `"ata="` (4 bytes) + 12 filler bytes (`"AAAAAAAAAAAA"`).
  - **Block 2 (bytes 32–47)**: User-crafted payload `":admin<true:"` (12 bytes) + suffix.
- Target characters and flips:
  - Byte 0 of Block 2: `':'` ($0\text{x}3A$) $\oplus$ `';'` ($0\text{x}3B$) = $0\text{x}01$. We flip $C_1[0]$ ($C[16]$) by $0\text{x}01$.
  - Byte 6 of Block 2: `'<'` ($0\text{x}3C$) $\oplus$ `'='` ($0\text{x}3D$) = $0\text{x}01$. We flip $C_1[6]$ ($C[22]$) by $0\text{x}01$.
  - Byte 11 of Block 2: `':'` ($0\text{x}3A$) $\oplus$ `';'` ($0\text{x}3B$) = $0\text{x}01$. We flip $C_1[11]$ ($C[27]$) by $0\text{x}01$.

#### 4. Execution Output & Verification
```
Normal Submission: 'You're the man now, dog' -> verify() = False
Direct Injection: ';admin=true;' -> sanitized to '%3Badmin%3Dtrue%3B' -> verify() = False
CBC Bit-Flipped Ciphertext -> verify() = True  [EXPLOIT SUCCESSFUL]
```

##### Question 2 Answers:
- **Why is this attack possible?**
  - Encryption alone (confidentiality) provides **no integrity or authenticity protection**. CBC mode is *malleable*: an attacker can predictably manipulate plaintext bits by flipping ciphertext bits in the preceding block without knowing the secret key. Block $P_1$ is corrupted into random bytes, but because the application only checks for the presence of `;admin=true;` in the decrypted stream, the garbled block $P_1$ is ignored and authentication succeeds.
- **What would this scheme need to prevent such attacks?**
  1. **Authenticated Encryption (AEAD)**: Use modern authenticated modes such as **AES-GCM** (Galois/Counter Mode) or **AES-CCM**, which compute an authentication tag over the ciphertext and associated data.
  2. **Message Authentication Code (MAC)**: Implement an **Encrypt-then-MAC** architecture using **HMAC-SHA256**. The recipient validates the HMAC tag *before* decrypting; any bit alteration immediately fails tag verification and aborts processing.

---

### Task 3: Performance Comparison (AES vs. RSA)

#### 1. OpenSSL Benchmark Results
Using OpenSSL speed testing tools, symmetric (AES-CBC) and asymmetric (RSA) operations were benchmarked:

##### Table 1: AES Throughput across Block Sizes (KB/s)
| Cipher / Block Size | 16 Bytes | 64 Bytes | 256 Bytes | 1024 Bytes | 8192 Bytes | 16384 Bytes |
|:-------------------|:---------|:---------|:----------|:-----------|:-----------|:------------|
| **AES-128-CBC** | 271,055.1 kB/s | 278,075.8 kB/s | 344,860.9 kB/s | 298,409.1 kB/s | 330,293.3 kB/s | 308,061.8 kB/s |
| **AES-192-CBC** | 224,396.8 kB/s | 257,914.7 kB/s | 260,821.0 kB/s | 254,501.4 kB/s | 219,867.4 kB/s | 273,569.1 kB/s |
| **AES-256-CBC** | 234,614.6 kB/s | 268,884.1 kB/s | 227,451.6 kB/s | 229,597.5 kB/s | 255,553.1 kB/s | 238,303.5 kB/s |

##### Table 2: RSA Operations Throughput (Operations / Second)
| RSA Key Size | Private Sign (sign/s) | Public Verify (verify/s) | Public Encrypt (enc/s) | Private Decrypt (dec/s) |
|:-------------|:----------------------|:-------------------------|:-----------------------|:------------------------|
| **512 bits**  | 11,457.9 | 126,962.3 | 129,282.7 | 10,142.3 |
| **1024 bits** | 2,634.0  | 55,437.9  | 47,351.1  | 2,222.1  |
| **2048 bits** | 361.8    | 18,131.8  | 15,518.2  | 398.7    |
| **4096 bits** | 56.2     | 4,745.8   | 5,839.1   | 59.0     |

*(Generated plots: `aes_performance.png` and `rsa_performance.png`)*

##### Question 3 Answers:
- **Comparison & Analysis**:
  1. **Throughput Magnitude**: AES achieves processing speeds on the order of **200–350 MB/s**, enabling real-time streaming encryption of gigabytes of data. In contrast, RSA-2048 handles only ~360 private sign/decrypt operations per second, operating on payloads smaller than the key size.
  2. **Asymmetric Operation Asymmetry**: In RSA, public key operations (encryption and signature verification) are **30× to 80× faster** than private key operations (decryption and signing). This occurs because RSA commonly uses a small public exponent (e.g., $e = 65537 = 2^{16}+1$, requiring only 17 modular squarings and 1 multiplication), whereas the private exponent $d$ is a full-length random integer requiring hundreds to thousands of full modular exponentiation operations.
  3. **Scaling with Key Size**: AES throughput scales linearly with round counts (10 rounds for 128-bit, 12 rounds for 192-bit, 14 rounds for 256-bit), showing only a minor ~20% throughput difference between AES-128 and AES-256. Conversely, RSA modular exponentiation complexity scales cubically ($\mathcal{O}(k^3)$); moving from RSA-1024 to RSA-4096 results in a **~47× slowdown** in signing speed (from 2,634 sign/s down to 56.2 sign/s).
  4. **Practical Engineering Implication (Hybrid Cryptosystems)**: Because public key algorithms are computationally expensive and cannot efficiently encrypt large data streams, modern cryptographic protocols (TLS 1.3, SSH, PGP, Signal) use **Hybrid Cryptography**: RSA or ECDH is used solely for asymmetric key exchange and digital signatures, establishing a shared session key to encrypt bulk data with high-speed symmetric ciphers (AES-GCM or ChaCha20-Poly1305).

---

### Source Code Listings

#### 1. `task1_modes.py` (ECB & CBC Implementation)
```python
import os
from Crypto.Cipher import AES

BLOCK_SIZE = 16

def generate_key(key_size: int = BLOCK_SIZE) -> bytes:
    return os.urandom(key_size)

def generate_iv(block_size: int = BLOCK_SIZE) -> bytes:
    return os.urandom(block_size)

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    padding = bytes([pad_len] * pad_len)
    return data + padding

def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid data length for PKCS#7 unpadding.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding value.")
    expected_padding = bytes([pad_len] * pad_len)
    if data[-pad_len:] != expected_padding:
        raise ValueError("Corrupted PKCS#7 padding.")
    return data[:-pad_len]

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pkcs7_pad(plaintext, BLOCK_SIZE)
    ciphertext = bytearray()
    for i in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[i:i + BLOCK_SIZE]
        ciphertext.extend(cipher.encrypt(block))
    return bytes(ciphertext)

def decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be a multiple of block size.")
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        decrypted_padded.extend(cipher.decrypt(block))
    return pkcs7_unpad(bytes(decrypted_padded), BLOCK_SIZE)

def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV must be exactly {BLOCK_SIZE} bytes.")
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pkcs7_pad(plaintext, BLOCK_SIZE)
    ciphertext = bytearray()
    previous_block = iv
    for i in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[i:i + BLOCK_SIZE]
        xored_block = xor_bytes(block, previous_block)
        encrypted_block = cipher.encrypt(xored_block)
        ciphertext.extend(encrypted_block)
        previous_block = encrypted_block
    return bytes(ciphertext)

def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0 or len(iv) != BLOCK_SIZE:
        raise ValueError("Invalid ciphertext or IV length.")
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded = bytearray()
    previous_block = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        current_block = ciphertext[i:i + BLOCK_SIZE]
        decrypted_intermediate = cipher.decrypt(current_block)
        plaintext_block = xor_bytes(decrypted_intermediate, previous_block)
        decrypted_padded.extend(plaintext_block)
        previous_block = current_block
    return pkcs7_unpad(bytes(decrypted_padded), BLOCK_SIZE)
```

#### 2. `task2_oracle_attack.py` (Oracle & CBC Bit-Flipping Exploit)
```python
from task1_modes import encrypt_cbc, decrypt_cbc, generate_key, generate_iv

SERVER_KEY = generate_key()
SERVER_IV = generate_iv()

def url_encode_special_chars(s: str) -> str:
    return s.replace(";", "%3B").replace("=", "%3D")

def submit(user_input: str) -> bytes:
    sanitized_input = url_encode_special_chars(user_input)
    prefix = "userid=456;userdata="
    suffix = ";session-id=31337"
    full_string = prefix + sanitized_input + suffix
    return encrypt_cbc(full_string.encode("utf-8"), SERVER_KEY, SERVER_IV)

def verify(ciphertext: bytes) -> bool:
    try:
        decrypted_bytes = decrypt_cbc(ciphertext, SERVER_KEY, SERVER_IV)
        decrypted_str = decrypted_bytes.decode("latin1")
        return ";admin=true;" in decrypted_str
    except (ValueError, KeyError, UnicodeDecodeError):
        return False

def cbc_bit_flip_attack():
    filler = "A" * 12
    target_payload = ":admin<true:"
    user_input = filler + target_payload
    orig_ciphertext = submit(user_input)
    
    modified_ct = bytearray(orig_ciphertext)
    block1_start = 16
    modified_ct[block1_start + 0] ^= (ord(':') ^ ord(';'))
    modified_ct[block1_start + 6] ^= (ord('<') ^ ord('='))
    modified_ct[block1_start + 11] ^= (ord(':') ^ ord(';'))
    
    return orig_ciphertext, bytes(modified_ct), verify(bytes(modified_ct))
```

---

### Conclusion & Key Takeaways
1. **Never use ECB mode for structured data**: ECB is deterministic and preserves plaintext patterns, making it insecure for non-random data.
2. **Confidentiality does not imply Integrity**: CBC mode protects data confidentiality against passive eavesdroppers, but is malleable against active attackers who can modify ciphertexts to alter decrypted plaintexts.
3. **Use Authenticated Encryption (AEAD)**: Modern production systems must employ AEAD (such as AES-GCM) or Encrypt-then-MAC (HMAC-SHA256) to ensure both privacy and tampering protection.
4. **Hybrid Cryptography balances performance and security**: Symmetric ciphers (AES) provide the high throughput required for data transmission, while asymmetric ciphers (RSA/ECC) provide secure key negotiation and non-repudiation.
