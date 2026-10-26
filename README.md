# ITH-XOF: Cryptographic Hash Framework (v2.2.0)

**ITH-XOF** is a mathematical, multi-binary cryptographic hash suite built in Rust. Moving away from traditional ARX trapdoors, it features a **Fixed-Degree Logically Non-Linear Permutation Layer** mapped over a 1600-bit state plane. The suite provides two independent binaries designed to balance performance against extreme security bounds.

## 📊 Variant Comparison & Cryptographic Trade-offs

| Parameter | Standard Edition (`src/bin/ith_standard.rs`) | Paranoid Edition (`src/bin/ith_paranoid.rs`) |
| :--- | :--- | :--- |
| **Capacity ($c$)** | 1024 bits (16 words) | 1536 bits (24 words) |
| **Rate ($r$)** | 576 bits (72 bytes) | 64 bits (8 bytes) |
| **Classical Security** | 512-bit Pre-image / 256-bit Collision | 768-bit Pre-image / 384-bit Collision |
| **Quantum Resistance** | 256-bit Grover-safe bound | 384-bit Grover-immune plane |
| **Performance Profile** | Fast throughput via multi-word block ingestion. | Low throughput due to ultra-high capacity squeezing. |

## 🧠 Architectural Overview

Both engines implement an advanced 24-round permutation logic ensuring perfect state bijection:
* **Linear Theta Layer ($\theta$):** A column-parity mapping that forces non-singular, uniform entropy distribution.
* **Non-Linear Chi Layer ($\chi$):** A quadratic bit-mixing mapping maintaining an algebraic degree of exactly 2 per round.
* **Diffusion Layer ($\rho / \pi$):** Transposes words combined with 25 distinct bit rotations to shatter linear carry chains.

## 💻 Compilation & Deployment

Compile both standalone executables simultaneously using Cargo:
```bash
cargo build --release
```

💻 CLI Usage
The engine supports native file hashing, arbitrary length stream squeezing, and automated verification modes. (Note: Replace ith_standard with ith_paranoid if you downloaded the paranoid version.)

1. Standard Hashing (Default 64 characters / 256 bits)
ith_standard.exe "C:\path\to\file.ext"
2. Extendable-Output Squeezing (e.g., 500 characters)
ith_standard.exe "C:\path\to\file.ext" 500
3. Automated Verification Mode (/check)
Automatically scales the internal XOF squeezing engine based on the input string length and verifies integrity:

ith_standard.exe "C:\path\to\file.ext" /check <hex_string>

