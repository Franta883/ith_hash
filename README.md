# ITH-Hash Suite: Cryptographic & Forensic Framework (v2.4.0)

**ITH-Hash Suite** is a unified mathematical framework written in Rust, offering two distinct cryptographic Extendable-Output Functions (XOF), a context-triggered piecewise fuzzy hashing tool, and an advanced zero-dependency structural metadata analyzer.

## 📊 Core Engine Comparison & Design Intents

| Binary Target | Engine Variant | Core Cryptographic Purpose | Core Architectural Mechanism |
| :--- | :--- | :--- | :--- |
| `ith_standard` | **Standard Cryptographic XOF** | High-throughput data signing with robust quantum resistance (256-bit safe bound) and Extendable-Output Squeezing. | 24-round permutation using a bijective Theta parity layer and a fixed quadratic Chi logic ($c = 1024$ bits). |
| `ith_paranoid` | **Paranoid Cryptographic XOF** | Ultra-high capacity parameter structure for maximum proof against multi-property quantum speedups with Extendable-Output Squeezing. | Maximum capacity configuration forcing tight 8-byte data ingestion segments ($c = 1536$ bits). |
| `ith_fuzzy` | **CTPS Forensic Hashing** | Similarity matching and rolling-window heuristic analysis via Gear Hash Matrix (CDC) to spot modified or obfuscated binaries. | 3-tiered pipeline utilizing an high-throughput Gear Matrix rolling hash, FNV-1a feature compression, and a Shannon Entropy overlay. |
| `ith_metadata` | **Structural Features Analyzer** | Generates order-independent invariant structural hashes and detects compiler origin language over Windows PE and Linux ELF binaries. | Pure byte-scanning COFF/IAT/EAT vector table extraction linked into a custom standalone RFC 6234 SHA-256 engine. |

## 🚀 Native Compilation & Quickstart

Compile all standalone executables simultaneously from source code using Cargo:

```bash
cargo build --release
```

Optimized targets are available within your build root environment at:
* `target/release/ith_standard.exe`
* `target/release/ith_paranoid.exe`
* `target/release/ith_fuzzy.exe`
* `target/release/ith_metadata.exe`

### Standard Hashing Execution Snippets:

```bash
# Generate Standard 256-bit secure XOF hash
target/release/ith_standard.exe "path/to/binary.dat"

# Compute Gear-CDC fuzzy forensic signature for similarity deployment
target/release/ith_fuzzy.exe "path/to/binary.dat"

# Extract structural PE/ELF metadata and compute invariant Structural SHA-256
target/release/ith_metadata.exe "path/to/binary.exe"
```

## 📄 License
This project is open-source under the MIT License.
