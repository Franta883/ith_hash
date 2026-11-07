# ITH-Hash Suite: Cryptographic, Forensic & Spectral Framework (v3.0.0)

**ITH-Hash Suite** is a unified mathematical framework written in Rust. Moving away from standard legacy architectures, it provides a comprehensive zero-dependency toolkit for post-quantum signatures, extendable squeezes, parallel tree integrity, and advanced binary similarity topo-mapping.

## 📊 Core Engine Comparison & Design Intents

| Binary Target | Engine Variant | Core Cryptographic Purpose | Core Architectural Mechanism |
| :--- | :--- | :--- | :--- |
| `ith_hash` | **Unified Cryptographic XOF** | High-throughput data signing with variable Extendable-Output Squeezing. | 24-round permutation supporting Standard ($c=1024$) and Paranoid ($c=1536$) runtime parameters. |
| `ith_tree` | **Parallel Merkle Tree Engine** | Multi-threaded tree structure for massive files with dynamic post-quantum capacity enhancement. | Segmented 1 MB leaf chunking processed across native threads, utilizing standard or boosted ($c=1536$) domain prefixes. |
| `ith_fuzzy` | **CTPS Forensic Hashing** | Similarity matching and rolling-window heuristic analysis via Gear Hash Matrix (CDC) to spot modified or obfuscated binaries. | 3-tiered pipeline utilizing a high-throughput Gear Matrix rolling hash, FNV-1a feature compression, and a Shannon Entropy overlay. |
| `ith_metadata` | **Structural Features Analyzer** | Generates order-independent invariant structural hashes and detects compiler origin language over Windows PE and Linux ELF binaries. | Pure byte-scanning COFF/IAT/EAT vector table extraction linked into a custom standalone RFC 6234 SHA-256 engine. |
| `ith_spectral` | **Spectral-Lattice Hash (SELH v2)** | Post-quantum hybrid hashing providing decoupled noiseless thermometer topology mapping ($<2\%$ strict Hamming distance stability). | Discrete Number-Theoretic Transform (NTT) with separate high-volatile LWE noisy roots and rigid Edwards curve curve sponges. |

## 🚀 Native Compilation & Quickstart

Compile all standalone executables simultaneously from source code using Cargo:

```bash
cargo build --release
```

Optimized targets are available within your build root environment at:
* `target/release/ith_hash.exe`
* `target/release/ith_tree.exe`
* `target/release/ith_fuzzy.exe`
* `target/release/ith_metadata.exe`
* `target/release/ith_spectral.exe`

### Standard Hashing Execution Snippets:

```bash
# Generate Standard 256-bit secure XOF hash (Default 64 characters)
target/release/ith_hash.exe "path/to/binary.dat"

# Squeeze custom long XOF digest string using Paranoid mode (e.g., 500 characters)
target/release/ith_hash.exe /paranoid "path/to/binary.dat" 500

# Compute Parallel Merkle Tree Root with Boosted 1536-bit capacity
target/release/ith_tree.exe "path/to/massive_file.iso" /boostc

# Compute Gear-CDC fuzzy forensic signature for similarity deployment
target/release/ith_fuzzy.exe "path/to/binary.dat"

# Extract structural PE/ELF metadata and compute invariant Structural SHA-256
target/release/ith_metadata.exe "path/to/binary.exe"

# Generate Post-Quantum Dual Spectral-Lattice Root and Mask (v2)
target/release/ith_spectral.exe "path/to/binary.exe"
```

## 📄 License
This project is open-source under the MIT License.
