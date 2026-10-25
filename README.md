# ITH-XOF: Ultra-High Capacity Cryptographic Engine v2.2.0

**ITH-XOF v2.2.0** is an extreme-parameter variant of the ITH cryptographic family. Designed specifically for environments that demand maximum theoretical security bounds, this version forces a highly aggressive **1536-bit Capacity** layout within a 1600-bit state plane. 

By shrinking the data ingestion window down to a single 64-bit word ($r = 64$), this engine maximizes mathematical entropy density, establishing a **768-bit classical** and **384-bit quantum-safe** collision resistance boundary.

> ⚠️ **THEORETICAL TRADE-OFF NOTICE:** Because the block size is locked at 8 bytes, the permutation function triggers significantly more often than the older versions. This engine prioritizes absolute mathematical non-invertibility over processing throughput.

## 🛡️ Paranoid Mode Security Layout

| Attribute | Specification | Cryptographic & Mathematical Benefit |
| :--- | :--- | :--- |
| **Core Design** | Sponge Construction | **Immune** to length-extension attacks. |
| **State Width (\(b\))** | 1600 bits (25 x 64-bit words) | Massive internal state plane preventing structural collisions. |
| **Rate (\(r\))** | **64 bits (8 bytes)** | Extreme high-density state protection; ingests exactly one word per iteration. |
| **Capacity (\(c\))** | **1536 bits (24 words)** | **768-bit classical** & **384-bit quantum-safe** bounds (Grover/BHT immune). |
| **Linear Layer (\(\theta\))** | Column-Parity Theta Mix | **Fully Bijective (100% Invertible).** Prevents kernel cancellation or parity decay across the 24-word hidden space. |
| **Diffusion Layer (\(\rho / \pi\))** | Rho-Shift & Shift-Shuffle Matrix | Combines inter-word transposition with 25 unique word-specific bit rotations to fracture s-box carry chains. |
| **Non-Linear Layer (\(\chi\))**| Quadratic Boolean Mapping | Fixed algebraic degree of exactly 2 via bitwise NOT, AND, and XOR across all planes. |
| **Asymmetrical Injection** | High-Order Constant Salts | Breaks word symmetry completely by spreading unique, multi-bit round constants and word-specific salt modifiers across the entire 64-bit plane. |

## 🚀 Installation & Compilation

Ensure you have Rust and Cargo installed, then build using the optimized release profile:

```bash
cargo build --release
```

## 💻 CLI Usage

The engine supports native file hashing, arbitrary length stream squeezing, and automated verification modes.

### 1. Standard Hashing
```bash
ith_hash.exe "C:\(\path\to\file.\)ext"
```

### 2. Extendable-Output Squeezing (e.g., 500 characters)
```bash
ith_hash.exe "C:\(\path\to\file.\)ext" 500
```

### 3. Automated Verification Mode (`/check`)
```bash
ith_hash.exe "C:\(\path\to\file.\)ext" /check <hex_string>
```

## 📄 License
This project is open-source under the MIT License.
