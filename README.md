# ITH-XOF: InternalTools Cryptographic Hash & Extendable-Output Function (v2.0.0)

**ITH-XOF v2.0.0** is an ultra-secure, math-hardened, next-generation cryptographic hash engine designed in Rust. Moving away from standard ARX architectures, version 2.0.0 implements a strict **Fixed-Degree Logically Non-Linear Permutation** combined with a full **Sponge Construction** framework.

The internal permutation loop enforces an exact algebraic degree of 2 per round over \(\mathbb{F}_2\), completely neutralizing algebraic SAT-solvers, linear/differential cryptanalysis, and quantum-preimage optimizations.

> ⚠️ **YOU HAVE TO RUN THE INSTALLER FOR THE DOSKEY MACRO TO WORK.**

## 🛡️ Security Architecture & Parameter Layout

| Attribute | Specification | Cryptographic & Mathematical Benefit |
| :--- | :--- | :--- |
| **Core Design** | Sponge Construction | **Immune** to length-extension attacks. |
| **State Width (b)** | 1600 bits (25 x 64-bit words) | Massive internal state plane preventing structural collisions. |
| **Rate (r)** | 576 bits (72 bytes) | Optimal block ingestion speed for an ultra-high capacity layout. |
| **Capacity (c)** | 1024 bits (16 words) | **Full 512-bit classical** & **256-bit quantum-safe** security bounds (Grover/BHT proof). |
| **Linear Layer (θ)** | Multi-Word Parity Theta Mix | High-diffusion bitwise XOR/rotations (Degree = 1) ensuring uniform entropy distribution. |
| **Non-Linear Layer (χ)**| Quadratic Boolean Mapping | Fixed algebraic degree of exactly 2 via bitwise NOT, AND, and XOR. Perfect state bijection across an odd state size (25). |
| **Diffusion Layer** | **Shift-Shuffle Matrix Transposition** | Inspired by Keccak (SHA-3) permutation with added unique word-specific bit rotations to completely fracture s-box carry chains. |
| **Padding Schema** | \(10^*1\) bitwise layout | Secure padding termination for safe multi-block data streaming. |

## 🚀 Installation & Compilation

Ensure you have Rust and Cargo installed, then clone the repository and build using the optimized release profile:

```bash
cargo build --release
```
The compiled binary will be located at `target/release/ith_hash.exe`.

## 💻 CLI Usage

The engine supports native file hashing, arbitrary length stream squeezing, and automated verification modes.

### 1. Standard Hashing (Default 64 characters / 256 bits)
```bash
Hash-File "C:\path\to\file.ext"
```

### 2. Extendable-Output Squeezing (e.g., 500 characters)
```bash
Hash-File "C:\path\to\file.ext" 500
```

### 3. Automated Verification Mode (`/check`)
Automatically scales the internal XOF squeezing engine based on the input string length and verifies integrity:
```bash
Hash-File "C:\path\to\file.ext" /check <hex_string>
```

### 🎛️ Windows Command Line Integration (Doskey)
To integrate it directly into your command prompt environment as a system native command, run the automated `DOSKEY_installer.ps1` PowerShell script. It maps the following native console interface:
```text
Hash-File=C:\InternalTools\ith_xof.exe \$*
```

## 📄 License
This project is open-source under the MIT License.
