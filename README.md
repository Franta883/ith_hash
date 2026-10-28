# ITH-Hash Suite: Hash family (v2.3.1)

**ITH-Hash Suite** is a unified mathematical framework written in Rust, offering two distinct cryptographic Extendable-Output Functions (XOF) alongside a context-triggered piecewise fuzzy hashing tool. This multi-binary suite provides developers and forensic analysts with an optimized balance of speed, post-quantum security, and file-similarity mapping.

## 📊 Core Engine Comparison & Design Intents

| Binary Target | Engine Variant | Core Cryptographic Purpose | Core Architectural Mechanism |
| :--- | :--- | :--- | :--- |
| `ith_standard` | **Standard Cryptographic XOF** | High-throughput data signing with robust quantum resistance (256-bit safe bound) and **Extendable-Output Squeezing**. | 24-round permutation using a bijective Theta parity layer and a fixed quadratic Chi logic ($c = 1024$ bits). |
| `ith_paranoid` | **Paranoid Cryptographic XOF** | Ultra-high capacity parameter structure for maximum proof against multi-property quantum speedups with **Extendable-Output Squeezing**. | Maximum capacity configuration forcing tight 8-byte data ingestion segments ($c = 1536$ bits). |
| `ith_fuzzy` | **CTPS Forensic Hashing** | Similarity matching and rolling-window heuristic analysis to spot modified or obfuscated binaries. | 3-tiered pipeline utilizing an Adler-32 rolling hash, FNV-1a feature compression, and a Shannon Entropy overlay. |

## 🧠 Permutation & Slicing Architecture

### 1. Cryptographic XOF Engines (`ith_standard` & `ith_paranoid`)
Both cryptographic implementations completely replace older ARX layers with mathematically sound, fixed-degree logical blocks to ensure uniform distribution and thwart SAT-solver cryptanalysis. Output generation utilizes a dedicated **Squeezing Phase (XOF)**, allowing the user to request an arbitrarily long hex digest:
* **Linear Theta Layer ($\theta$):** A column-parity vector transformation ensuring 100% invertible state mappings.
* **Non-Linear Chi Layer ($\chi$):** An optimized mapping maintaining an exact algebraic degree of 2 per iteration.
* **Diffusion Layer ($\rho / \pi$):** Transposes and rotates individual words to prevent carry-chain linearity leakage.
* **Extendable Output (XOF):** If the requested length exceeds the rate $r$, the internal state runs additional permutation cycles natively, squeezing unlimited unique bits from the internal state layout.

### 2. Forensic Engine (`ith_fuzzy`)
The Context-Triggered Piecewise Signature (CTPS) engine shifts bounds dynamically based on content matching:
* **Dynamic Chunking:** Triggers data-stream cutting only when the sliding Adler-32 window hits a specific modulo marker, neutralizing file-size shift deficiencies.
* **Dual-Scale Ingestion:** Operates parallel tracking at block size $B$ and $2B$ to catch structural matches if sizes shift significantly.
* **Entropy Anchor:** Factorizes localized Shannon entropy to block evasion techniques that merely scramble chunk locations.

## 🚀 Native Compilation & Quickstart

Download The Ready Executables, Or Compile all standalone executables simultaneously from source code using Cargo:

```bash
cargo build --release
```

Optimized targets are available within your build root environment at:
* `target/release/ith_standard.exe`
* `target/release/ith_paranoid.exe`
* `target/release/ith_fuzzy.exe`

### Standard Execution Snippets:

```bash
# Generate Standard 256-bit secure XOF hash (Default 64 characters)
target/release/ith_standard.exe "path/to/binary.dat"

# Squeeze custom long XOF digest string using the Standard engine (e.g., 500 characters)
target/release/ith_standard.exe "path/to/binary.dat" 500

# Squeeze extreme post-quantum XOF digest string using the Paranoid engine (e.g., 1000 characters)
target/release/ith_paranoid.exe "path/to/binary.dat" 1000

# Verify file state using Standard automated check mode
target/release/ith_standard.exe "path/to/binary.dat" /check <hex_string>

# Compute CTPS fuzzy forensic signature for similarity deployment
target/release/ith_fuzzy.exe "path/to/binary.dat"
```

## 📄 License
This project is open-source under the MIT License.
