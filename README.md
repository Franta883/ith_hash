# ITH-Hash Family: Cryptographic, Forensic & Spectral Framework (v2.5.2)

**ITH-Hash Suite** is a unified mathematical framework written in Rust. Moving away from standard legacy architectures, it provides a comprehensive zero-dependency toolkit for post-quantum signatures, extendable squeezes, and advanced binary similarity topo-mapping.

## Core Engine Comparison & Design Intents

| Binary Target | Engine Variant | Core Cryptographic Purpose | Core Architectural Mechanism |
| :--- | :--- | :--- | :--- |
| `ith_standard` | **Standard Cryptographic XOF** | High-throughput data signing with robust quantum resistance (256-bit safe bound) and Extendable-Output Squeezing. | 24-round permutation using a bijective Theta parity layer and a fixed quadratic Chi logic ($c = 1024$ bits). |
| `ith_paranoid` | **Paranoid Cryptographic XOF** | Ultra-high capacity parameter structure for maximum proof against multi-property quantum speedups with Extendable-Output Squeezing. | Maximum capacity configuration forcing tight 8-byte data ingestion segments ($c = 1536$ bits). |
| `ith_fuzzy` | **CTPS Forensic Hashing** | Similarity matching and rolling-window heuristic analysis via Gear Hash Matrix (CDC) to spot modified or obfuscated binaries. | 3-tiered pipeline utilizing a high-throughput Gear Matrix rolling hash, FNV-1a feature compression, and a Shannon Entropy overlay. |
| `ith_metadata` | **Structural Features Analyzer** | Generates order-independent invariant structural hashes and detects compiler origin language over Windows PE and Linux ELF binaries. | Pure byte-scanning COFF/IAT/EAT vector table extraction linked into a custom standalone RFC 6234 SHA-256 engine. |
| `ith_spectral` | **Spectral-Lattice Hash (SELH v2)** | Post-quantum hybrid hashing providing decoupled noiseless thermometer topology mapping ($<2\%$ strict Hamming distance stability). | Discrete Number-Theoretic Transform (NTT) with separate high-volatile LWE noisy roots and rigid Edwards curve curve sponges. |

## Permutation & Slicing Architecture

### 1. Cryptographic XOF Engines (`ith_standard` & `ith_paranoid`)
Both cryptographic implementations completely replace older ARX layers with mathematically sound, fixed-degree logical blocks to ensure uniform distribution and thwart SAT-solver cryptanalysis. Output generation utilizes a dedicated **Squeezing Phase (XOF)**, allowing the user to request an arbitrarily long hex digest.

### 2. Forensic Engine (`ith_fuzzy`)
The Context-Triggered Piecewise Signature (CTPS) engine shifts bounds dynamically based on content matching using a fast 64-bit `GEAR_MATRIX` lookup table.

### 3. Spectral-Lattice Engine (`ith_spectral`)
The SELH v2 engine processes data through a fully quantized integer-only pipeline to eliminate architecture-dependent floating-point divergence:
* **Discrete NTT Layer:** Cooley-Tukey Radix-2 transform operating over a finite Goldilocks field $\mathbb{F}_q$ to extract deterministic frequency spectra.
* **Bifurcated LWE Projection:** Volatile CSPRNG Gaussian noise is injected *exclusively* into the state path heading toward the 64-byte Rigid Root. 
* **Thermometer Topology:** The signature mask extracts structural features *pre-noise*, scaling them via an 8-bit Gray-coded thermometer lookup table to lock an ultra-stable biometrical binary footprint.

## Native Compilation & Quickstart

Compile all five standalone executables simultaneously from source code using Cargo:

```bash
cargo build --release
```

Optimized targets are available within your build root environment at:
* `target/release/ith_standard.exe`
* `target/release/ith_paranoid.exe`
* `target/release/ith_fuzzy.exe`
* `target/release/ith_metadata.exe`
* `target/release/ith_spectral.exe`

### Standard Hashing Execution Snippets:

```bash
# Generate Standard 256-bit secure XOF hash (Default 64 characters)
target/release/ith_standard.exe "path/to/binary.dat"

# Squeeze custom long XOF digest string using the Standard engine (e.g., 500 characters)
target/release/ith_standard.exe "path/to/binary.dat" /500

# Compute Gear-CDC fuzzy forensic signature for similarity deployment
target/release/ith_fuzzy.exe "path/to/binary.dat"

# Extract structural PE/ELF metadata and compute invariant Structural SHA-256
target/release/ith_metadata.exe "path/to/binary.exe"

# Generate Post-Quantum Dual Spectral-Lattice Root and Mask (v2)
target/release/ith_spectral.exe "path/to/binary.exe"
```

## 📄 License
This project is open-source under the MIT License.
