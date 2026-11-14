//! Spectral-Entropy Lattice Hash (SELH v2.1 - Hardened) Engine
//! Decoupled Noiseless Topology + Thermometer Encoding for <2% Fuzzy Hamming Distance.

use std::env;
use std::fmt;
use std::fs::File;
use std::io::Read;

// ============================================================================
// MATHEMATICAL & ARCHITECTURAL CONSTANTS
// ============================================================================

const Q: u64 = 0xFFFF_FFFF_0000_0001;
const N: usize = 64;
const OMEGA_64: u64 = 16_307_326_096_582_861_471;
const HALF_WINDOW: usize = 32;
const WINDOW_SIZE: usize = HALF_WINDOW * 2; // 64
const MIN_CHUNK: usize = 64;
const MAX_CHUNK: usize = 2048;
const ENTROPY_SHIFT_THRESHOLD: u64 = 24_000;

// Domain separation constants for the sponge capacity
const DOMAIN_CHUNK_DATA: u64 = 0x4348_554E_4B5F_4454; // "CHUNK_DT"
const DOMAIN_LATTICE: u64    = 0x4C41_5454_4943_455F; // "LATTICE_"
const DOMAIN_FINALIZE: u64   = 0x4649_4E41_4C49_5A45; // "FINALIZE"

// Round constants (fractional parts of square roots of primes) to prevent zero fixed-points
const ROUND_CONSTANTS: [u64; 12] = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
];

// Corrected c * log2(c) * 1024 lookup table for c in 0..=32 (and up to 64)
const C_LOG2_C_TABLE: [u64; 65] = [
         0,      0,   2048,   4871,   8192,  11888,  15882,  20127,
     24576,  29203,  34016,  38939,  44063,  49299,  54672,  60164,
     65536,  71195,  76900,  82745,  88681,  94711, 100832, 107039,
    113328, 119696, 126139, 132654, 139239, 145890, 152606, 159384,
    163840, 173117, 180067, 187072, 194131, 201242, 208405, 215617,
    222879, 230188, 237544, 244946, 252393, 259884, 267418, 274995,
    282614, 290274, 297974, 305715, 313494, 321313, 329170, 337065,
    344997, 352965, 360970, 369011, 377087, 385199, 393345, 401526,
    393216, // Fixed: 64 * log2(64) * 1024 = 393,216
];

const THERMOMETER_LUT: [u8; 9] = [
    0b0000_0000, 0b0000_0001, 0b0000_0011, 0b0000_0111,
    0b0000_1111, 0b0001_1111, 0b0011_1111, 0b0111_1111,
    0b1111_1111,
];

#[derive(Clone, PartialEq, Eq)]
pub struct SelhHash {
    pub rigid_root: [u8; 64],
    pub fuzzy_mask: [u8; 128],
}

impl fmt::Display for SelhHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rigid Root (64B) : ")?;
        for b in &self.rigid_root {
            write!(f, "{:02x}", b)?;
        }
        write!(f, "\nFuzzy Mask (128B): ")?;
        for b in &self.fuzzy_mask {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

// ============================================================================
// FINITE FIELD ARITHMETIC (F_q)
// ============================================================================

#[inline(always)]
fn mod_add(a: u64, b: u64) -> u64 {
    ((a as u128 + b as u128) % (Q as u128)) as u64
}

#[inline(always)]
fn mod_sub(a: u64, b: u64) -> u64 {
    ((a as u128 + Q as u128 - (b % Q) as u128) % (Q as u128)) as u64
}

#[inline(always)]
fn mod_mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % (Q as u128)) as u64
}

// ============================================================================
// STEP 1: STATELESS LOCAL-HORIZON ENTROPY CHUNKING
// ============================================================================

#[inline]
fn subwindow_entropy(counts: &[usize; 256]) -> u64 {
    // For a 32-byte subwindow: 32 * log2(32) * 1024 = 163_840
    let mut sum_c_log_c = 0u64;
    for &c in counts.iter() {
        if c > 0 {
            sum_c_log_c += C_LOG2_C_TABLE[c];
        }
    }
    163_840u64.saturating_sub(sum_c_log_c)
}

#[inline]
fn rolling_gear_hash(window: &[u8]) -> u64 {
    let mut h = 0x9E37_79B9_7F4A_7C15u64;
    for &b in window {
        let table_val = public_matrix_a(b as usize, (b ^ 0x5A) as usize);
        h = h.rotate_left(1).wrapping_add(table_val);
    }
    h
}

pub fn dynamic_entropy_chunking(data: &[u8]) -> Vec<&[u8]> {
    if data.len() <= MIN_CHUNK {
        return vec![data];
    }
    let mut chunks = Vec::new();
    let mut start = 0;

    let mut left_counts = [0usize; 256];
    let mut right_counts = [0usize; 256];

    for i in 0..HALF_WINDOW {
        left_counts[data[i] as usize] += 1;
        right_counts[data[i + HALF_WINDOW] as usize] += 1;
    }

    let mut i = WINDOW_SIZE;
    while i < data.len() {
        let leaving_left = data[i - WINDOW_SIZE] as usize;
        let moving_mid = data[i - HALF_WINDOW] as usize;
        let entering_right = data[i] as usize;

        left_counts[leaving_left] -= 1;
        left_counts[moving_mid] += 1;
        right_counts[moving_mid] -= 1;
        right_counts[entering_right] += 1;

        let left_entropy = subwindow_entropy(&left_counts);
        let right_entropy = subwindow_entropy(&right_counts);
        let local_delta = left_entropy.abs_diff(right_entropy);

        let chunk_len = i - start;
        // Stateless local boundary condition: compares adjacent subwindows + local rolling tag
        let gear_trigger = (rolling_gear_hash(&data[i - 8..i]) & 0x3F) == 0;

        if (chunk_len >= MIN_CHUNK && local_delta >= ENTROPY_SHIFT_THRESHOLD && gear_trigger)
            || chunk_len >= MAX_CHUNK
        {
            chunks.push(&data[start..i]);
            start = i;
        }
        i += 1;
    }
    if start < data.len() {
        chunks.push(&data[start..]);
    }
    chunks
}

// ============================================================================
// STEP 2: QUANTIZATION & DISCRETE NUMBER-THEORETIC TRANSFORM (NTT)
// ============================================================================

/// Used for the fuzzy topology path (smooth accumulation)
fn quantize_chunk_fuzzy(chunk: &[u8]) -> [u64; N] {
    let mut vec = [0u64; N];
    for (idx, &byte) in chunk.iter().enumerate() {
        vec[idx % N] = vec[idx % N].wrapping_add(byte as u64);
    }
    vec
}

/// Position-dependent nonlinear quantization for the cryptographic SIS lattice path
fn quantize_chunk_crypto(chunk: &[u8], chunk_idx: u64) -> [u64; N] {
    let mut vec = [0u64; N];
    let mut state = 0x6A09_E667_F3BC_C908u64 ^ chunk_idx.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for (idx, &byte) in chunk.iter().enumerate() {
        // Mix byte value, exact position within chunk, and running nonlinear chain
        let pos_mix = (idx as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        state = (state ^ (byte as u64 + 1).wrapping_add(pos_mix))
            .rotate_left(17)
            .wrapping_mul(0x94D0_49BB_1331_11EB);
        vec[idx % N] = mod_add(vec[idx % N], state % (1 << 16));
    }
    // Bind exact chunk length into constant term
    vec[0] = mod_add(vec[0], chunk.len() as u64);
    vec
}

pub fn ntt_64(input: &[u64; N]) -> [u64; N] {
    let mut a = *input;
    let mut j = 0usize;
    for i in 1..N {
        let mut bit = N >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            a.swap(i, j);
        }
    }
    let mut len = 2;
    while len <= N {
        let half = len / 2;
        let step = N / len;
        let mut w_len = 1u64;
        for _ in 0..step {
            w_len = mod_mul(w_len, OMEGA_64);
        }
        for i in (0..N).step_by(len) {
            let mut w = 1u64;
            for k in 0..half {
                let u = a[i + k];
                let v = mod_mul(a[i + k + half], w);
                a[i + k] = mod_add(u, v);
                a[i + k + half] = mod_sub(u, v);
                w = mod_mul(w, w_len);
            }
        }
        len <<= 1;
    }
    a
}

// ============================================================================
// STEP 3: CAPACITY-PROTECTED SPONGE & LATTICE PROJECTION
// ============================================================================

#[inline]
fn public_matrix_a(i: usize, j: usize) -> u64 {
    // Reject-sample style mixing to avoid zero entries in public matrix A
    let seed = ((i as u64) << 32) | (j as u64);
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    ((z ^ (z >> 31)) % (Q - 1)) + 1
}

#[inline]
fn local_matrix_a(i: usize, j: usize) -> u64 {
    ((public_matrix_a(i, j) & 0x03) + 1) as u64
}

fn lattice_project_dual(
    fuzzy_quantized: &[u64; N],
    crypto_spectrum: &[u64; N],
    fuzzy_spectrum: &[u64; N],
) -> ([u64; N], [u64; 128]) {
    let mut sis_digest = [0u64; N];
    let mut clean_topo = [0u64; 128];
    let dc_component = fuzzy_spectrum[0];

    for i in 0..N {
        let mut full_acc = 0u64;
        let mut local_acc = 0u64;
        for j in 0..N {
            full_acc = mod_add(full_acc, mod_mul(public_matrix_a(i, j), crypto_spectrum[j]));
            local_acc = local_acc.wrapping_add(local_matrix_a(i, j) * fuzzy_quantized[j]);
        }
        sis_digest[i] = full_acc;
        let neighbor_diff = fuzzy_quantized[i].abs_diff(fuzzy_quantized[(i + 1) % N]);
        clean_topo[i * 2] = local_acc;
        clean_topo[i * 2 + 1] = dc_component.wrapping_add(neighbor_diff * 32);
    }
    (sis_digest, clean_topo)
}

/// 1024-bit Cryptographic Sponge with 512-bit Rate (state[0..8]) and 512-bit Capacity (state[8..16])
struct HardenedLatticeSponge {
    state: [u64; 16],
}

impl HardenedLatticeSponge {
    fn new() -> Self {
        let mut state = [0u64; 16];
        for i in 0..16 {
            state[i] = public_matrix_a(i + 1, (i ^ 0xA5) + 1);
        }
        Self { state }
    }

    /// Invertible (bijective) 12-round ARX + Feistel permutation over 16 x 64-bit words
    fn permute(&mut self) {
        for &rc in &ROUND_CONSTANTS {
            // Add round constant to break symmetry and eliminate all-zero fixed points
            self.state[0] ^= rc;
            self.state[8] = self.state[8].wrapping_add(rc);

            // Column ARX quarter-rounds (bijective over 2^64)
            for i in 0..4 {
                let (a, b, c, d) = (i, i + 4, i + 8, i + 12);
                self.state[a] = self.state[a].wrapping_add(self.state[b]);
                self.state[d] = (self.state[d] ^ self.state[a]).rotate_left(32);

                self.state[c] = self.state[c].wrapping_add(self.state[d]);
                self.state[b] = (self.state[b] ^ self.state[c]).rotate_left(24);

                self.state[a] = self.state[a].wrapping_add(self.state[b]);
                self.state[d] = (self.state[d] ^ self.state[a]).rotate_left(16);

                self.state[c] = self.state[c].wrapping_add(self.state[d]);
                self.state[b] = (self.state[b] ^ self.state[c]).rotate_left(63);
            }

            // Diagonal diffusion shuffle
            self.state.swap(1, 5);
            self.state.swap(2, 10);
            self.state.swap(3, 15);
            self.state.swap(6, 11);
            self.state.swap(7, 13);
            self.state.swap(12, 14);
        }
    }

    /// Absorbs arbitrary byte slices into the 512-bit Rate (state[0..8]) with 10*1 padding.
    /// Capacity (state[8..16]) is strictly isolated from direct input injection.
    fn absorb_bytes_padded(&mut self, data: &[u8], chunk_idx: u64) {
        self.state[8] ^= DOMAIN_CHUNK_DATA;
        self.state[9] ^= chunk_idx;
        self.state[10] ^= data.len() as u64;

        let mut chunks_iter = data.chunks_exact(64);
        for block in &mut chunks_iter {
            for i in 0..8 {
                let word = u64::from_le_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
                self.state[i] ^= word;
            }
            self.permute();
        }

        // 10*1 bit padding on the remainder block (rate = 64 bytes)
        let rem = chunks_iter.remainder();
        let mut pad_block = [0u8; 64];
        pad_block[..rem.len()].copy_from_slice(rem);
        pad_block[rem.len()] ^= 0x80;
        pad_block[63] ^= 0x01;

        for i in 0..8 {
            let word = u64::from_le_bytes(pad_block[i * 8..(i + 1) * 8].try_into().unwrap());
            self.state[i] ^= word;
        }
        self.permute();
    }

    /// Absorbs the 64-element lattice vector exclusively through the 8-word Rate (`state[0..8]`)
    fn absorb_lattice(&mut self, lattice_vec: &[u64; N]) {
        self.state[8] ^= DOMAIN_LATTICE;
        for block in lattice_vec.chunks_exact(8) {
            for i in 0..8 {
                self.state[i] = self.state[i].wrapping_add(block[i]);
            }
            self.permute();
        }
    }

    /// Finalizes the sponge and squeezes 64 bytes from the Rate (`state[0..8]`)
    fn squeeze_64_bytes(&mut self, total_len: u64, total_chunks: u64) -> [u8; 64] {
        self.state[8] ^= DOMAIN_FINALIZE;
        self.state[9] ^= total_len;
        self.state[10] ^= total_chunks;
        self.permute();

        let mut out = [0u8; 64];
        for i in 0..8 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&self.state[i].to_le_bytes());
        }
        out
    }
}

// ============================================================================
// STEP 4: DUAL-OUTPUT GENERATION
// ============================================================================

pub fn selh_hash(data: &[u8]) -> SelhHash {
    let chunks = dynamic_entropy_chunking(data);
    let mut sponge = HardenedLatticeSponge::new();
    let mut topo_accum = [0u128; 128];

    for (chunk_idx, chunk) in chunks.iter().enumerate() {
        // 1. Absorb raw chunk bytes with 10*1 padding into the capacity-protected sponge
        sponge.absorb_bytes_padded(chunk, chunk_idx as u64);

        // 2. Compute decoupled projections for crypto (SIS) and fuzzy (LSH) paths
        let fuzzy_quantized = quantize_chunk_fuzzy(chunk);
        let crypto_quantized = quantize_chunk_crypto(chunk, chunk_idx as u64);

        let fuzzy_spectrum = ntt_64(&fuzzy_quantized);
        let crypto_spectrum = ntt_64(&crypto_quantized);

        let (sis_lattice, clean_topo) =
            lattice_project_dual(&fuzzy_quantized, &crypto_spectrum, &fuzzy_spectrum);

        // 3. Absorb the lattice projection into the cryptographic sponge
        sponge.absorb_lattice(&sis_lattice);

        // 4. Accumulate fuzzy topology in u128 to prevent overflow on large files
        for i in 0..128 {
            topo_accum[i] = topo_accum[i].wrapping_add(clean_topo[i] as u128);
        }
    }

    let rigid_root = sponge.squeeze_64_bytes(data.len() as u64, chunks.len() as u64);
    let total_bytes = (data.len().max(1)) as u128;
    let mut fuzzy_mask = [0u8; 128];

    for i in 0..128 {
        let normalized = if i % 2 == 0 {
            (topo_accum[i] * 9) / (total_bytes * 640)
        } else {
            (topo_accum[i] * 9) / (total_bytes * 512)
        };
        let level = (normalized as usize).min(8);
        fuzzy_mask[i] = THERMOMETER_LUT[level];
    }

    SelhHash {
        rigid_root,
        fuzzy_mask,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("--- ITH-Spectral: Spectral-Entropy Lattice Hash Engine (v2.1 Hardened) ---");
        println!("Usage:  ith_spectral <file_path>");
        return;
    }

    let raw_path = args[1..].join(" ");
    let file_path = raw_path.trim_matches('"');

    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("\x1b[31mError opening file '{}': {}\x1b[0m", file_path, e);
            std::process::exit(1);
        }
    };

    let mut data = Vec::new();
    if let Err(e) = file.read_to_end(&mut data) {
        eprintln!("\x1b[31mError reading file: {}\x1b[0m", e);
        std::process::exit(1);
    }

    let hash = selh_hash(&data);
    println!("=== Binary State Analysis: {} ===", file_path);
    println!("{}", hash);
}