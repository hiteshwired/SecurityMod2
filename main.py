import matplotlib.pyplot as plt
from PIL import Image

import task1_modes
import task2_oracle_attack
import task3_performance


def run_task1():
    print("\n=== Task 1: ECB vs CBC ===")

    bmp_path = "mustang.bmp"
    ecb_out = "mustang_ecb.bmp"
    cbc_out = "mustang_cbc.bmp"

    print("Encrypting the mustang BMP with ECB...")
    key_ecb = task1_modes.encrypt_bmp_ecb(bmp_path, ecb_out)
    print(f"  key: {key_ecb.hex()}")
    print(f"[debug] wrote {ecb_out}")

    print("Encrypting the mustang BMP with CBC...")
    key_cbc, iv_cbc = task1_modes.encrypt_bmp_cbc(bmp_path, cbc_out)
    print(f"  key: {key_cbc.hex()}")
    print(f"  iv:  {iv_cbc.hex()}")

    print("Building comparison figure (bmp_comparison.png)...")
    fig, axes = plt.subplots(1, 3, figsize=(13.5, 4.2), dpi=150)
    fig.subplots_adjust(wspace=0.15)

    axes[0].imshow(Image.open(bmp_path))
    axes[0].set_title("original pic", fontfamily="monospace")
    axes[0].axis("off")

    axes[1].imshow(Image.open(ecb_out))
    axes[1].set_title("ECB\n(yeah you can still tell it's a car)", color="#b83227", fontfamily="monospace")
    axes[1].axis("off")

    axes[2].imshow(Image.open(cbc_out))
    axes[2].set_title("CBC\n(just noise, nice)", color="#238b45", fontfamily="monospace")
    axes[2].axis("off")

    plt.tight_layout()
    plt.savefig("bmp_comparison.png")
    plt.close()

    # same round-trip check but on a plain text file instead of an image
    plaintext = b"SJSU beat Cal Poly at the football game. Bummer."
    with open("plaintext.txt", "wb") as f:
        f.write(plaintext)

    print("Testing round-trip encryption/decryption on a text file...")
    ecb_key = task1_modes.encrypt_file_ecb("plaintext.txt", "plaintext_ecb.enc")
    with open("plaintext_ecb.enc", "rb") as f:
        assert task1_modes.decrypt_ecb(f.read(), ecb_key) == plaintext
    print("  ECB round-trip OK")

    cbc_key, cbc_iv = task1_modes.encrypt_file_cbc("plaintext.txt", "plaintext_cbc.enc")
    with open("plaintext_cbc.enc", "rb") as f:
        assert task1_modes.decrypt_cbc(f.read(), cbc_key, cbc_iv) == plaintext
    print("  CBC round-trip OK")


def run_task2():
    print("\n=== Task 2: CBC Bit-Flipping Attack ===")

    normal_input = "You're the man now, dog"
    ct = task2_oracle_attack.submit(normal_input)
    print(f"submit('{normal_input}') -> verify() = {task2_oracle_attack.verify(ct)}")

    injected_input = ";admin=true;"
    ct = task2_oracle_attack.submit(injected_input)
    print(f"submit('{injected_input}') -> verify() = {task2_oracle_attack.verify(ct)} (blocked by sanitization)")

    print("Running the CBC bit-flipping attack...")
    orig_ct, tampered_ct, success = task2_oracle_attack.cbc_bit_flip_attack()
    print(f"  original ciphertext length: {len(orig_ct)} bytes")
    print(f"  tampered ciphertext length: {len(tampered_ct)} bytes")
    print(f"  verify(tampered) = {success}")
    if success:
        print("  got admin access without ever knowing the key")


def run_task3():
    print("\n=== Task 3: AES vs RSA performance ===")

    aes_data = task3_performance.run_aes_benchmark()
    rsa_data = task3_performance.run_rsa_benchmark()

    task3_performance.plot_aes_performance(aes_data, "aes_performance.png")
    task3_performance.plot_rsa_performance(rsa_data, "rsa_performance.png")


def main():
    print("CSC-3201 Symmetric Key Cryptography Lab - running all tasks")

    run_task1()
    run_task2()
    run_task3()

    print("\nDone - all three tasks ran without errors.")


if __name__ == "__main__":
    main()