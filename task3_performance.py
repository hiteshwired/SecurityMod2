import re
import subprocess

import matplotlib.pyplot as plt

OPENSSL = "openssl"


def run_aes_benchmark() -> dict:
    print(f"Benchmarking AES with openssl ('{OPENSSL}')...")

    block_sizes = [16, 64, 256, 1024, 8192, 16384]
    result = subprocess.run(
        [OPENSSL, "speed", "-seconds", "1", "aes-128-cbc", "aes-192-cbc", "aes-256-cbc"],
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr

    parsed = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith(("aes-128-cbc", "aes-192-cbc", "aes-256-cbc")):
            parts = line.split()
            cipher_name = parts[0]
            rates = [float(p.replace("k", "")) for p in parts[1:7]]
            parsed[cipher_name] = dict(zip(block_sizes, rates))

    return parsed


def run_rsa_benchmark() -> dict:
    # same idea, but for RSA key sizes 512/1024/2048/4096
    print(f"Benchmarking RSA with openssl ('{OPENSSL}')...")

    # matches: rsa 2048 bits 0.002762s 0.000090s ... 361.8 18131.8 ...
    line_pattern = re.compile(
        r"^rsa\s+(\d+)\s+bits\s+[\d.]+s\s+[\d.]+s\s+[\d.]+s\s+[\d.]+s\s+"
        r"([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)"
    )

    result = subprocess.run(
        [OPENSSL, "speed", "-seconds", "1", "rsa512", "rsa1024", "rsa2048", "rsa4096"],
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr

    parsed = {}
    for line in output.splitlines():
        match = line_pattern.match(line.strip())
        if match:
            key_size, sign, verify, enc, dec = match.groups()
            parsed[int(key_size)] = {
                "sign_ops": float(sign),
                "verify_ops": float(verify),
                "encrypt_ops": float(enc),
                "decrypt_ops": float(dec),
            }

    return parsed


def plot_aes_performance(aes_data: dict, output_file: str = "aes_performance.png") -> None:
    plt.figure(figsize=(9, 5.5), dpi=150)

    display_names = {"aes-128-cbc": "AES-128-CBC", "aes-192-cbc": "AES-192-CBC", "aes-256-cbc": "AES-256-CBC"}
    colors = {"aes-128-cbc": "#e63946", "aes-192-cbc": "#457b9d", "aes-256-cbc": "#2a9d8f"}
    markers = {"aes-128-cbc": "o", "aes-192-cbc": "D", "aes-256-cbc": "^"}

    for cipher_name, block_rates in aes_data.items():
        sizes = sorted(block_rates.keys())
        throughput_mb = [block_rates[s] / 1000.0 for s in sizes]  # kB/s -> MB/s

        plt.plot(
            [str(s) for s in sizes],
            throughput_mb,
            marker=markers.get(cipher_name, "o"),
            color=colors.get(cipher_name, "blue"),
            linewidth=2,
            markersize=6,
            label=display_names.get(cipher_name, cipher_name),
        )

    plt.title("AES: does a bigger key actually slow things down?", fontsize=13, fontweight="bold")
    plt.xlabel("Block Size (bytes)")
    plt.ylabel("Throughput (MB/s)")
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.legend(title="Key size")
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()
    print(f"Saved {output_file}")


def plot_rsa_performance(rsa_data: dict, output_file: str = "rsa_performance.png") -> None:
    plt.figure(figsize=(9, 5.5), dpi=150)

    key_sizes = sorted(rsa_data.keys())
    x_labels = [f"{k} bits" for k in key_sizes]

    series_labels = ["Public verify", "Public encrypt", "Private sign", "Private decrypt"]
    series_keys = ["verify_ops", "encrypt_ops", "sign_ops", "decrypt_ops"]
    series_colors = ["#2ca02c", "#1f77b4", "#d62728", "#9467bd"]
    series_markers = ["o", "s", "^", "v"]
    series = []
    for label, key, color, marker in zip(series_labels, series_keys, series_colors, series_markers):
        values = [rsa_data[k][key] for k in key_sizes]
        series.append((label, values, color, marker))

    for label, values, color, marker in series:
        linestyle = "--" if label == "Private sign" else "-"
        plt.plot(
            x_labels, values, marker=marker, color=color, linewidth=2, markersize=6,
            linestyle=linestyle, label=label,
        )

    verify_at_4096 = rsa_data[4096]["verify_ops"]
    plt.annotate(
        "verify is way faster than sign here",
        xy=(x_labels[-1], verify_at_4096),
        xytext=(-95, -25),
        textcoords="offset points",
        fontsize=8,
        arrowprops=dict(arrowstyle="->", color="gray"),
    )

    plt.yscale("log")
    plt.title("RSA Throughput vs. Key Size", fontsize=13, fontweight="bold")
    plt.xlabel("RSA key size")
    plt.ylabel("ops/sec (log scale, bigger keys = slower)")
    plt.grid(True, which="both", linestyle="--", alpha=0.6)
    plt.legend(title="Which operation", loc="lower left")
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()
    print(f"Saved {output_file}")


if __name__ == "__main__":
    print("Task 3 - OpenSSL Speed Benchmarking")
    print("-" * 40)

    aes_results = run_aes_benchmark()
    rsa_results = run_rsa_benchmark()

    print("\nAES results (kB/s):")
    for name, rates in aes_results.items():
        print(f"  {name}: {rates}")

    print("\nRSA results (ops/sec):")
    for size, rates in rsa_results.items():
        print(f"  RSA-{size}: {rates}")

    plot_aes_performance(aes_results)
    plot_rsa_performance(rsa_results)
