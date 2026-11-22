# ITH-Hash Suite: Cryptographic, Forensic & Spectral Framework (v4.0.0)

**ITH-Hash Suite** is a unified, zero-dependency cryptographic and forensic framework written in Rust under strict **`#![deny(unsafe_code)]`** enforcement. Moving away from legacy architectures, it provides a memory-hardened toolkit for post-quantum signatures, stateful extendable-output squeezes (XOF), parallel Merkle tree integrity, static PE/ELF binary analysis, and dual-scale forensic similarity mapping.

---

## 🆕 What's New in v4.0.0

* **3D Bit-Sliced State Geometry (`[[u64; 5]; 5]`):** Upgraded the internal permutation matrix from flat `[u64; 25]` arrays to true 3D bit-sliced state lanes indexed as `state[x][y]` and `KECCAK_RHO[x][y]` using linear coordinate mapping ($x = i \bmod 5, y = \lfloor i / 5 \rfloor$).
* **Paranoid-by-Default & Cryptographic Domain Separation:** Changed the default profile of `ith_hash` from Standard to **Paranoid** ($c = 1536, r = 64$), making `/standard` ($c = 1024, r = 576$) an explicit opt-in flag. Replaced generic `0x01` padding with profile-specific domain separation suffixes (`0x06` for Paranoid, `0x0A` for Standard) prior to `pad10*1` termination to guarantee cross-profile output independence.
* **Stateful Sponge Phase Locking (`IthHasher`):** Replaced stateless one-shot arrays with a dedicated `IthHasher` state machine that isolates hidden capacity lanes, enforces phase locking (`finalized: bool`) to reject `absorb()` calls once squeezing begins, and supports sequential multi-call XOF streaming via `squeeze()`.
* **Volatile Memory Zeroization & Hardened Constant-Time Check:** Enforced `#![deny(unsafe_code)]` across the crate, implemented `volatile_zero_u64_grid` and `volatile_zero_bytes` with `Ordering::SeqCst` compiler fences inside `impl Drop for IthHasher`, and hardened `constant_time_eq` using `core::ptr::read_volatile` to prevent dead-store elimination and branch timing leaks.

---

## 🛡️ Security & Hardening Architecture

### 1. Core Stateful XOF & Tree Engines (`ith_hash` & `ith_tree`)
* **3D Keccak-f Dispersion & Asymmetric Constants:** Full 3D coordinate dispersion $(x, y) \mapsto (y, (2x + 3y) \bmod 5)$ paired with row-wise quadratic $\chi$ mapping (algebraic degree 2) and single-lane asymmetric LFSR round constants ($\iota$) injected into `state[0][0]`.
* **Domain-Separated `pad10*1` Alignment:** Eliminates collision ambiguity between Standard (`0x0A`) and Paranoid (`0x06`) profiles while cleanly handling single-block boundary alignments.
* **Merkle Tree Internal Width & Second-Preimage Defense:** Locks all internal Merkle nodes to 512 bits (128 hex characters) regardless of requested output length and enforces strict domain prefixes (`LEAF:`, `NODE:`, `NODE_ODD:`).
* **Delimiter Injection & Symlink Loop Prevention:** Prefixes directory records with explicit byte lengths (`DIR:len:path`, `FILE:len:path:size:hash`, `SYMLINK:len:path:target_len:target`) and inspects `entry.file_type()` directly so symlinks are hashed as metadata rather than traversed infinitely.
* **Interrupted I/O & Overflow Protection:** Uses `read_full` loops against OS-interrupted reads and enforces explicit `u64` offset arithmetic (`(chunk_idx as u64) * (CHUNK_SIZE_1MB as u64)`) to prevent 32-bit integer overflows.

### 2. Forensic Fuzzy Engine (`ith_fuzzy`)
* **Gear Hash MSB Boundary Trigger:** Uses MSB inspection (`(rolling_hash >> (64 - bits)) == 0`) so all 64 bits of the sliding window participate in chunk boundary detection.
* **Compile-Time SplitMix64 `GEAR_MATRIX`:** Generates 256 deterministic, high-entropy 64-bit constants at compile time via SplitMix64.
* **FNV-1a Full-Width XOR Folding:** Folds all 32 bits of the FNV-1a chunk digest into the 6-bit Base64 index so upper byte bits (`0xC0`) contribute equally.
* **5-Part Scale-Aligned Signature (`B:Sig_B:Ent_B:Sig_2B:Ent_2B`):** Folds trailing stream data past 64 chunks into the 64th signature character and pairs separate Shannon entropy anchors to both $B$ and $2B$ scales.
* **Bounded Memory Execution:** Streams files through a 64 KB `BufReader` and computes Levenshtein edit distance using a bounded $O(\min(N, M))$ 2-row rolling array.

### 3. Static Metadata & Spectral Engines (`ith_metadata` & `ith_spectral`)
* **Division-by-Zero & Checked Offset Guards (`ith_metadata`):** Guards ELF section/symbol entry table divisions (`size.checked_div(entsize)`) against malformed zero-sized entries, enforces `checked_add` across PE Import Directory offsets, and runs a standalone RFC 6234 SHA-256 engine.
* **Decoupled Noiseless Topology (`ith_spectral`):** Separates volatile LWE Gaussian noise (used strictly for the 64-byte Edwards-curve Rigid Root) from the pre-noise NTT spectral accumulator, stabilizing the 128-byte Gray-coded thermometer Fuzzy Mask against single-bit avalanche distortion.

---

## 📊 Core Engine Comparison & Design Intents

| Binary Target | Engine Variant | Core Purpose | Architectural Mechanism |
| :--- | :--- | :--- | :--- |
| `ith_hash` | **Stateful Cryptographic XOF** | High-security file & directory signing with memory zeroization and Extendable-Output Squeezing. | 24-round 3D bit-sliced `IthHasher` defaulting to **Paranoid** ($c=1536$, suffix `0x06`) with opt-in `/standard` ($c=1024$, suffix `0x0A`), `/folder`, and `/usemerkletree`. |
| `ith_tree` | **Parallel Merkle Tree Engine** | Multi-threaded tree hashing for massive files with dynamic post-quantum capacity scaling. | Concurrent 1 MB leaf chunk hashing across native OS threads with domain separation (`0x00`/`0x01`) and `/boostc` ($c=1536$). |
| `ith_fuzzy` | **CTPS Forensic Hashing** | Content-defined similarity matching to detect modified, padded, or rearranged binaries. | Streaming 64-bit SplitMix64 Gear Hash, XOR-folded FNV-1a compression, and dual-scale Shannon entropy anchors. |
| `ith_metadata` | **Structural Features Analyzer** | Generates order-independent invariant structural hashes and detects compiler language (PE & ELF). | Zero-dependency byte-level IAT/EAT/section extraction paired with a standalone RFC 6234 SHA-256 implementation. |
| `ith_spectral` | **Spectral-Lattice Hash (SELH v2)** | Post-quantum hybrid hashing combining a rigid curve root with a low-Hamming-distance topology mask. | Integer-only Goldilocks-field ($\mathbb{F}_q$) Cooley-Tukey NTT, bifurcated LWE projection, and Gray-coded thermometer encoding. |

---

## 🚀 Native Compilation & Quickstart

Compile all five standalone executables simultaneously from source code using Cargo:

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
# 1. Stateful XOF File & Directory Hashing (ith_hash - defaults to Paranoid c=1536)
target/release/ith_hash.exe "path/to/file.dat"
target/release/ith_hash.exe /standard "path/to/file.dat" 500
target/release/ith_hash.exe /folder /usemerkletree "path/to/directory" 128
target/release/ith_hash.exe "path/to/file.dat" /check <expected_hash>

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
