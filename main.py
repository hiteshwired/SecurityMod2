"""
Main Execution Script for CSC-3201 Symmetric Key Cryptography Lab
CSC-3201: Introduction to Computer Security

This script executes all three tasks in sequence:
  Task 1: AES-128 ECB & CBC implementations and BMP image encryption.
  Task 2: Authentication Oracle and CBC Bit-Flipping Attack demonstration.
  Task 3: OpenSSL Speed Benchmarking & Matplotlib performance plotting.
"""

import matplotlib.pyplot as plt
from PIL import Image

import task1_modes
import task2_oracle_attack
import task3_performance
import generate_sample_bmp


def run_task1():
    print("\n" + "=" * 65)
    print("TASK 1: Modes of Operation (ECB vs. CBC)")
    print("=" * 65)
    
    # 1. Generate sample BMP image
    bmp_path = "sample.bmp"
    ecb_bmp_path = "sample_ecb.bmp"
    cbc_bmp_path = "sample_cbc.bmp"
    
    print("[+] Creating sample 24-bit BMP image...")
    generate_sample_bmp.create_sample_bmp(bmp_path)
    
    # 2. Encrypt BMP using custom ECB and CBC modes (preserving 54-byte header)
    print("[+] Encrypting BMP image in ECB mode (block-by-block)...")
    key_ecb = task1_modes.encrypt_bmp_ecb(bmp_path, ecb_bmp_path)
    print(f"    Key (hex): {key_ecb.hex()}")
    print(f"    Saved ECB ciphertext BMP to: {ecb_bmp_path}")
    
    print("[+] Encrypting BMP image in CBC mode (block-by-block with IV)...")
    key_cbc, iv_cbc = task1_modes.encrypt_bmp_cbc(bmp_path, cbc_bmp_path)
    print(f"    Key (hex): {key_cbc.hex()}")
    print(f"    IV  (hex): {iv_cbc.hex()}")
    print(f"    Saved CBC ciphertext BMP to: {cbc_bmp_path}")
    
    # 3. Create visual comparison figure
    print("[+] Generating side-by-side visual comparison figure...")
    fig, axes = plt.subplots(1, 3, figsize=(13, 4.5), dpi=150)
    
    orig_img = Image.open(bmp_path)
    ecb_img = Image.open(ecb_bmp_path)
    cbc_img = Image.open(cbc_bmp_path)
    
    axes[0].imshow(orig_img)
    axes[0].set_title("Original Plaintext Image", fontsize=11, fontweight="bold")
    axes[0].axis("off")
    
    axes[1].imshow(ecb_img)
    axes[1].set_title("Encrypted Image (ECB Mode)\n[Pattern Leaked]", fontsize=11, fontweight="bold", color="#d62728")
    axes[1].axis("off")
    
    axes[2].imshow(cbc_img)
    axes[2].set_title("Encrypted Image (CBC Mode)\n[Pseudorandom Noise]", fontsize=11, fontweight="bold", color="#2ca02c")
    axes[2].axis("off")
    
    plt.tight_layout()
    comparison_path = "bmp_comparison.png"
    plt.savefig(comparison_path)
    plt.close()
    print(f"    Comparison plot saved to: {comparison_path}")
    
    # 4. Test text file encryption & round-trip decryption
    sample_text = b"Confidential Data: Exploring Symmetric Key Cryptography and Block Cipher Modes!"
    test_txt_path = "sample_plaintext.txt"
    test_ecb_path = "sample_ecb.enc"
    test_cbc_path = "sample_cbc.enc"
    
    with open(test_txt_path, "wb") as f:
        f.write(sample_text)
        
    print("\n[+] Testing file encryption and round-trip decryption on text...")
    k_txt_ecb = task1_modes.encrypt_file_ecb(test_txt_path, test_ecb_path)
    with open(test_ecb_path, "rb") as f:
        dec_ecb = task1_modes.decrypt_ecb(f.read(), k_txt_ecb)
    assert dec_ecb == sample_text, "ECB round-trip failed"
    print("    [PASS] File ECB encryption and decryption verified.")
    
    k_txt_cbc, iv_txt_cbc = task1_modes.encrypt_file_cbc(test_txt_path, test_cbc_path)
    with open(test_cbc_path, "rb") as f:
        dec_cbc = task1_modes.decrypt_cbc(f.read(), k_txt_cbc, iv_txt_cbc)
    assert dec_cbc == sample_text, "CBC round-trip failed"
    print("    [PASS] File CBC encryption and decryption verified.")


def run_task2():
    print("\n" + "=" * 65)
    print("TASK 2: Limits of Confidentiality & CBC Bit-Flipping Attack")
    print("=" * 65)
    
    # Test safe input
    safe_str = "You're the man now, dog"
    print(f"[+] Normal User Submission: '{safe_str}'")
    ct_safe = task2_oracle_attack.submit(safe_str)
    res_safe = task2_oracle_attack.verify(ct_safe)
    print(f"    verify(submit('{safe_str}')) -> {res_safe}")
    
    # Test direct injection attempt (should be URL encoded and fail)
    inject_str = ";admin=true;"
    print(f"\n[+] Direct Injection Attempt: '{inject_str}'")
    ct_inject = task2_oracle_attack.submit(inject_str)
    res_inject = task2_oracle_attack.verify(ct_inject)
    print(f"    verify(submit('{inject_str}')) -> {res_inject} (Blocked by URL sanitization)")
    
    # Perform CBC bit flipping attack
    print("\n[+] Executing CBC Bit-Flipping Attack...")
    orig_ct, mod_ct, attack_res = task2_oracle_attack.cbc_bit_flip_attack()
    print(f"    Original Ciphertext Length : {len(orig_ct)} bytes")
    print(f"    Modified Ciphertext Length : {len(mod_ct)} bytes")
    print(f"    Attack Success (verify == True): {attack_res}")
    
    if attack_res:
        print("    [SUCCESS] Admin privilege escalation achieved via ciphertext manipulation!")


def run_task3():
    print("\n" + "=" * 65)
    print("TASK 3: Performance Comparison (AES vs. RSA)")
    print("=" * 65)
    
    print("[+] Gathering OpenSSL throughput metrics...")
    aes_metrics = task3_performance.run_aes_benchmark()
    rsa_metrics = task3_performance.run_rsa_benchmark()
    
    print("\n[+] Generating Performance Plots...")
    task3_performance.plot_aes_performance(aes_metrics, "aes_performance.png")
    task3_performance.plot_rsa_performance(rsa_metrics, "rsa_performance.png")
    print("    [COMPLETE] Performance comparison plots generated successfully.")


def main():
    print("CSC-3201: Introduction to Computer Security")
    print("Symmetric Key Cryptography Exploration Lab")
    print("Running full automated test suite...")
    
    run_task1()
    run_task2()
    run_task3()
    
    print("\n" + "=" * 65)
    print("ALL TASKS COMPLETED SUCCESSFULLY!")
    print("=" * 65)


if __name__ == "__main__":
    main()
