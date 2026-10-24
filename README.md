# ITH-XOF: InternalTools Cryptographic Hash & Extendable-Output Function

**ITH-XOF** is a high-security, ultra-fast cryptographic hash engine designed in Rust. It utilizes a modern **Sponge Construction** combined with an **ARX (Addition-Rotation-XOR)** permutation loop. 

Unlike traditional hashes, ITH-XOF functions as an **Extendable-Output Function (XOF)**, allowing users to request an arbitrarily long hex digest from a single file layout.

## 🛡️ Security Architecture

| Attribute | Specification | Cryptographic Benefit |
| :--- | :--- | :--- |
| **Core Design** | Sponge Construction | **Immune** to length-extension attacks. |
| **State Width (b)** | 1600 bits (25 x 64-bit words) | Massive internal state space to prevent collisions. |
| **Rate (r)** | 1088 bits (136 bytes) | High-speed data absorption per block iteration. |
| **Capacity (c)** | 512 bits | Ensures **256-bit quantum-safe** security level. |
| **Permutation (f)** | 24 rounds of custom ARX | Constant-time execution natively shielding against side-channel timing attacks. |
| **Padding Schema** | \(10^*1\) bitwise layout | Secure padding handling for multi-block data streams. |

## 🚀 Installation & Compilation

Ensure you have Rust and Cargo installed, then clone the repository and build using the optimized release profile:

```bash
cargo build --release
```
The compiled binary will be located at `target/release/ith_hash.exe`.

## 💻 CLI Usage

The engine supports native file hashing, arbitrary length stream squeezing, and automated verification modes. YOU HAVE TO RUN THE INSTALLER FOR THE DOSKEY MACRO TO WORK.

### 1. Standard Hashing (Default 64 characters / 256 bits)
```bash
ith_hash.exe "C:\path\to\file.ext"
```

### 2. Extendable-Output Squeezing (e.g., 500 characters)
```bash
ith_hash.exe "C:\path\to\file.ext" 500
```

### 3. Automated Verification Mode (`/check`)
Automatically scales the internal XOF squeezing engine based on the input string length and verifies integrity:
```bash
ith_hash.exe "C:\path\to\file.ext" /check <hex_string>
```

### 🎛️ Windows Command Line Integration (Doskey)
To integrate it directly into your command prompt environment as a system native command, add this alias to your macro file:
```text
Hash-File=C:\InternalTools\ith_xof.exe \$*
```

## 📄 License
This project is under the MIT License.
