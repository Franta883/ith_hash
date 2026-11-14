# ITH-Hash Suite: Cryptographic, Forensic & Spectral Framework (v3.2.0)

**ITH-Hash Suite** is a unified, zero-dependency mathematical framework written in Rust. Moving away from legacy architectures, it provides a hardened toolkit for post-quantum signatures, extendable-output squeezes (XOF), parallel Merkle tree integrity, static PE/ELF binary analysis, and dual-scale forensic similarity mapping.

---

## 🆕 What's New in v3.2.0

* **Full 2D Keccak-f Geometry (`ith_hash` & `ith_tree`):** Upgraded the permutation engine from 1D index shuffling to true 2D coordinate dispersion $(x, y) \mapsto (y, (2x + 3y) \bmod 5)$ paired with row-wise quadratic $\chi$ mapping and asymmetric LFSR round constants ($\iota$).
* **Hardened Directory & Merkle Tree Engine (`ith_hash`):** Added `/folder` and `/usemerkletree` modes with length-prefixed canonical records, full 512-bit internal Merkle node widths, and explicit tracking of empty directories and symlinks.
* **5-Part Dual-Scale Fuzzy Format (`ith_fuzzy`):** Replaced the 4-part signature with `B:Sig_B:Ent_B:Sig_2B:Ent_2B`, aligning Shannon entropy anchors to both $B$ and $2B$ block granularities.
* **Constant-Time Verification Oracle (`/check`):** Enforced strict hexadecimal validation, a 32-character (128-bit) minimum length floor, order-independent CLI argument parsing, and constant-time comparison across the suite.
* **Streaming & Memory Hardening:** Eliminated full-file RAM buffering in favor of fixed-size `BufReader` streaming across large datasets.

---

## 🛡️ Security Audit & Vulnerabilities Fixed

Every module in the suite underwent a comprehensive cryptographic and systems audit to eliminate theoretical and runtime flaws:

### 1. Core XOF & Tree Engines (`ith_hash` & `ith_tree`)
* **2D Inter-Column Dispersion & Symmetry Removal:** Replaced the 1D `(i * 7) % 25` shuffle and column-symmetric round constants (which partially canceled out in the $\theta$ parity layer) with full 2D Keccak-f $\pi$, $\chi$, and single-lane $\iota$ round constants.
* **Single-Block `pad10*1` Alignment:** Fixed edge-case multi-block padding behavior when remaining bytes equaled `block_size - 1`, collapsing padding cleanly into `0x81`.
* **Merkle Tree Internal Width & Second-Preimage Defense:** Prevented weak internal tree collisions when short XOF output lengths are requested by locking all internal Merkle nodes to 512 bits (128 hex characters) and enforcing strict domain prefixes (`LEAF:`, `NODE:`, `NODE_ODD:`).
* **Delimiter Injection & Symlink Loop Prevention:** Added explicit byte-length prefixes to directory records (`DIR:len:path`, `FILE:len:path:size:hash`, `SYMLINK:len:path:target_len:target`) and switched to `entry.file_type()` so symlinks are hashed as metadata rather than followed infinitely.
* **Interrupted `read()` Handling:** Added `read_full` loops to prevent partial disk or OS-interrupted reads from prematurely truncating file streams.

### 2. Forensic Fuzzy Engine (`ith_fuzzy`)
* **Gear Hash MSB Boundary Trigger:** Fixed a rolling-window collapse where LSB modulo (`rolling_hash % b`) only inspected the lowest $\log_2(b)$ bits and locked out even `GEAR_MATRIX` entries. Shifted to MSB inspection (`(rolling_hash >> (64 - bits)) == 0`) so all 64 bits of the sliding window participate.
* **Compile-Time SplitMix64 `GEAR_MATRIX`:** Replaced biased and duplicated table constants with 256 deterministic, high-entropy 64-bit values generated at compile time via SplitMix64.
* **FNV-1a Upper-Bit Folding:** Fixed a mathematical blind spot where `% 64` ignored the upper 2 bits (`0xC0`) of every input byte by XOR-folding all 32 bits of the FNV-1a state into the 6-bit Base64 index.
* **Suffix Tail-Folding & Scale-Aligned Entropy:** Prevented blind truncation after 64 chunks by folding remaining file data into the 64th signature character, and paired separate entropy anchors to both $B$ and $2B$ scales.
* **DoS & OOM Mitigation:** Replaced `read_to_end` with a 64 KB `BufReader` stream and reduced Levenshtein distance memory from $O(N \times M)$ to a bounded $O(\min(N, M))$ 2-row rolling buffer.

### 3. Static Metadata & Spectral Engines (`ith_metadata` & `ith_spectral`)
* **Bounds-Checked Binary Parsing (`ith_metadata`):** Hardened COFF, PE IAT/EAT, and ELF section/symbol table offsets against malformed or truncated headers while keeping standalone RFC 6234 SHA-256 computation free of external dependencies.
* **Decoupled Noiseless Topology (`ith_spectral`):** Separated volatile LWE Gaussian noise (used strictly for the 64-byte Edwards-curve Rigid Root) from the pre-noise NTT spectral accumulator, stabilizing the 128-byte Gray-coded thermometer Fuzzy Mask against single-bit avalanche distortion.

---

## 📊 Core Engine Comparison & Design Intents

| Binary Target | Engine Variant | Core Purpose | Architectural Mechanism |
| :--- | :--- | :--- | :--- |
| `ith_hash` | **Unified Cryptographic XOF** | High-throughput file & directory signing with variable Extendable-Output Squeezing. | 24-round 2D Keccak-f permutation supporting Standard ($c=1024$) and Paranoid ($c=1536$) modes, plus `/folder` and `/usemerkletree`. |
| `ith_tree` | **Parallel Merkle Tree Engine** | Multi-threaded tree hashing for massive files with dynamic post-quantum capacity scaling. | Concurrent 1 MB leaf chunk hashing across native OS threads with domain separation (`0x00`/`0x01`) and `/boostc` ($c=1536$). |
| `ith_fuzzy` | **CTPS Forensic Hashing** | Content-defined similarity matching to detect modified, padded, or rearranged binaries. | Streaming 64-bit SplitMix64 Gear Hash, XOR-folded FNV-1a compression, and dual-scale Shannon entropy anchors. |
| `ith_metadata` | **Structural Features Analyzer** | Generates order-independent invariant structural hashes and detects compiler language (PE & ELF). | Zero-dependency byte-level IAT/EAT/section extraction paired with a standalone RFC 6234 SHA-256 implementation. |
| `ith_spectral` | **Spectral-Lattice Hash (SELH v2)** | Post-quantum hybrid hashing combining a rigid curve root with a low-Hamming-distance topology mask. | Integer-only Goldilocks-field ($\mathbb{F}_q$) Cooley-Tukey NTT, bifurcated LWE projection, and Gray-coded thermometer encoding. |

---

## 🚀 Native Compilation & Quickstart

To preserve source verification and ensure absolute repository trust, this suite does not distribute pre-compiled binaries. Compile all five standalone executables simultaneously from source code using Cargo:

```bash
cargo build --release
```

Optimized binaries will be generated at:
* `target/release/ith_hash.exe`
* `target/release/ith_tree.exe`
* `target/release/ith_fuzzy.exe`
* `target/release/ith_metadata.exe`
* `target/release/ith_spectral.exe`

### Execution Snippets

```bash
# 1. Unified XOF File & Directory Hashing (ith_hash)
target/release/ith_hash.exe /standard "path/to/file.dat"
target/release/ith_hash.exe /paranoid "path/to/file.dat" 500
target/release/ith_hash.exe /folder /usemerkletree "path/to/directory" 128
target/release/ith_hash.exe /standard "path/to/file.dat" /check <expected_hash>

# 2. Multi-Threaded File Merkle Tree (ith_tree)
target/release/ith_tree.exe "path/to/massive_file.iso"
target/release/ith_tree.exe /boostc "path/to/massive_file.iso"

# 3. Forensic Fuzzy Hashing & Comparison (ith_fuzzy)
target/release/ith_fuzzy.exe "path/to/binary.exe"
target/release/ith_fuzzy.exe /compare "<hash_1>" "<hash_2>"

# 4. PE/ELF Structural Metadata & Invariant SHA-256 (ith_metadata)
target/release/ith_metadata.exe "path/to/binary.exe"

# 5. Post-Quantum Dual Spectral-Lattice Hash (ith_spectral)
target/release/ith_spectral.exe "path/to/binary.exe"
```

---

## 📄 License

This project is open-source under the MIT License.
