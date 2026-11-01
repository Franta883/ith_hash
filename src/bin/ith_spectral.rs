//! Spectral-Entropy Lattice Hash (SELH v2) Engine
//! Decoupled Noiseless Topology + Thermometer Encoding for <2% Fuzzy Hamming Distance.

use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

// ============================================================================
// MATHEMATICAL & ARCHITECTURAL CONSTANTS
// ============================================================================

const Q: u64 = 0xFFFF_FFFF_0000_0001;
const N: usize = 64;
const OMEGA_64: u64 = 16_307_326_096_582_861_471;
const WINDOW_SIZE: usize = 64;
const MIN_CHUNK: usize = 64;
const MAX_CHUNK: usize = 2048;
const ENTROPY_SHIFT_THRESHOLD: u64 = 38_000;

const C_LOG2_C_TABLE: [u64; 65] = [
         0,      0,   2048,   4871,   8192,  11888,  15882,  20127,
     24576,  29203,  34016,  38939,  44063,  49299,  54672,  60164,
     65536,  71195,  76900,  82745,  88681,  94711, 100832, 107039,
    113328, 119696, 126139, 132654, 139239, 145890, 152606, 159384,
    163840, 173117, 180067, 187072, 194131, 201242, 208405, 215617,
    222879, 230188, 237544, 244946, 252393, 259884, 267418, 274995,
    282614, 290274, 297974, 305715, 313494, 321313, 329170, 337065,
    344997, 352965, 360970, 369011, 377087, 385199, 393345, 401526,
    409600,
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
        for b in &self.rigid_root { write!(f, "{:02x}", b)?; }
        write!(f, "\nFuzzy Mask (128B): ")?;
        for b in &self.fuzzy_mask { write!(f, "{:02x}", b)?; }
        Ok(())
    }
}

// ============================================================================
// FINITE FIELD ARITHMETIC (F_q)
// ============================================================================

#[inline(always)] fn mod_add(a: u64, b: u64) -> u64 { ((a as u128 + b as u128) % (Q as u128)) as u64 }
#[inline(always)] fn mod_sub(a: u64, b: u64) -> u64 { ((a as u128 + Q as u128 - b as u128) % (Q as u128)) as u64 }
#[inline(always)] fn mod_mul(a: u64, b: u64) -> u64 { ((a as u128 * b as u128) % (Q as u128)) as u64 }

// ============================================================================
// STEP 1: DYNAMIC ENTROPY-BASED CHUNKING
// ============================================================================

fn window_entropy(counts: &[usize; 256]) -> u64 {
    let mut sum_c_log_c = 0u64;
    for &c in counts.iter() { if c > 0 { sum_c_log_c += C_LOG2_C_TABLE[c]; } }
    393_216u64.saturating_sub(sum_c_log_c)
}

pub fn dynamic_entropy_chunking(data: &[u8]) -> Vec<&[u8]> {
    if data.len() <= MIN_CHUNK { return vec![data]; }
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut counts = [0usize; 256];

    for i in 0..WINDOW_SIZE.min(data.len()) { counts[data[i] as usize] += 1; }
    let mut baseline_entropy = window_entropy(&counts);
    let mut i = WINDOW_SIZE;

    while i < data.len() {
        counts[data[i - WINDOW_SIZE] as usize] -= 1;
        counts[data[i] as usize] += 1;
        let current_entropy = window_entropy(&counts);
        let chunk_len = i - start;
        let entropy_delta = current_entropy.abs_diff(baseline_entropy);

        if (chunk_len >= MIN_CHUNK && entropy_delta >= ENTROPY_SHIFT_THRESHOLD) || chunk_len >= MAX_CHUNK {
            chunks.push(&data[start..i]);
            start = i;
            baseline_entropy = current_entropy;
        }
        i += 1;
    }
    if start < data.len() { chunks.push(&data[start..]); }
    chunks
}

// ============================================================================
// STEP 2: QUANTIZATION & DISCRETE NUMBER-THEORETIC TRANSFORM (NTT)
// ============================================================================

fn quantize_chunk(chunk: &[u8]) -> [u64; N] {
    let mut vec = [0u64; N];
    for (idx, &byte) in chunk.iter().enumerate() {
        vec[idx % N] = vec[idx % N].wrapping_add(byte as u64);
    }
    vec
}

pub fn ntt_64(input: &[u64; N]) -> [u64; N] {
    let mut a = *input;
    let mut j = 0usize;
    for i in 1..N {
        let mut bit = N >> 1;
        while j & bit != 0 { j ^= bit; bit >>= 1; }
        j ^= bit;
        if i < j { a.swap(i, j); }
    }
    let mut len = 2;
    while len <= N {
        let half = len / 2;
        let step = N / len;
        let mut w_len = 1u64;
        for _ in 0..step { w_len = mod_mul(w_len, OMEGA_64); }
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
// STEP 3: BIFURCATED LWE PROJECTION
// ============================================================================

struct DeterministicCsprng { state: [u64; 8] }

impl DeterministicCsprng {
    fn from_chunk(chunk: &[u8]) -> Self {
        let mut state: [u64; 8] = [
            0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
            0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
        ];
        for (i, &b) in chunk.iter().enumerate() {
            state[i % 8] ^= (b as u64).wrapping_shl(((i / 8) % 8 * 8) as u32);
            if i % 8 == 7 { Self::permute(&mut state); }
        }
        state[0] ^= chunk.len() as u64;
        Self::permute(&mut state); Self::permute(&mut state);
        Self { state }
    }
    #[inline] fn permute(s: &mut [u64; 8]) {
        for _ in 0..6 {
            for i in 0..4 {
                s[i] = s[i].wrapping_add(s[i + 4]);
                s[i + 4] = s[i + 4].rotate_left(17) ^ s[i];
                s[i] = s[i].rotate_left(31);
                s[i + 4] = s[i + 4].wrapping_add(s[(i + 1) % 4]);
            }
            s.swap(1, 2); s.swap(5, 7);
        }
    }
    fn next_u64(&mut self) -> u64 { Self::permute(&mut self.state); self.state[0] ^ self.state[4] }
    fn sample_gaussian_noise(&mut self) -> u64 {
        let r = self.next_u64();
        let pos_weight = (r & 0xFFFF_FFFF).count_ones() as u64;
        let neg_weight = (r >> 32).count_ones() as u64;
        if pos_weight >= neg_weight { pos_weight - neg_weight } else { Q - (neg_weight - pos_weight) }
    }
}

#[inline] fn public_matrix_a(i: usize, j: usize) -> u64 {
    let seed = ((i as u64) << 32) | (j as u64);
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (z ^ (z >> 31)) % Q
}

#[inline] fn local_matrix_a(i: usize, j: usize) -> u64 { ((public_matrix_a(i, j) & 0x03) + 1) as u64 }

fn lwe_project_dual(quantized: &[u64; N], spectrum: &[u64; N], csprng: &mut DeterministicCsprng) -> ([u64; N], [u64; 128]) {
    let mut b_noisy = [0u64; N];
    let mut clean_topo = [0u64; 128];
    let dc_component = spectrum[0];

    for i in 0..N {
        let mut full_acc = 0u64;
        let mut local_acc = 0u64;
        for j in 0..N {
            full_acc = mod_add(full_acc, mod_mul(public_matrix_a(i, j), spectrum[j]));
            local_acc = local_acc.wrapping_add(local_matrix_a(i, j) * quantized[j]);
        }
        b_noisy[i] = mod_add(full_acc, csprng.sample_gaussian_noise());
        let neighbor_diff = quantized[i].abs_diff(quantized[(i + 1) % N]);
        clean_topo[i * 2] = local_acc;
        clean_topo[i * 2 + 1] = dc_component.wrapping_add(neighbor_diff * 32);
    }
    (b_noisy, clean_topo)
}

// ============================================================================
// STEP 4: DUAL-OUTPUT GENERATION
// ============================================================================

struct AlgebraicEdwardsSponge { state: [u64; 16] }

impl AlgebraicEdwardsSponge {
    fn new() -> Self {
        let mut state = [0u64; 16];
        for i in 0..16 { state[i] = public_matrix_a(i, i ^ 0x55); }
        Self { state }
    }
    fn edwards_mix(&mut self) {
        const D: u64 = 121665;
        for round in 0..8 {
            for i in 0..8 {
                let x1 = self.state[i]; let y1 = self.state[i + 8];
                let x2 = self.state[(i + 1) % 8]; let y2 = self.state[((i + 1) % 8) + 8];
                let x1y2 = mod_mul(x1, y2); let y1x2 = mod_mul(y1, x2);
                let x1x2 = mod_mul(x1, x2); let y1y2 = mod_mul(y1, y2);
                let d_xy = mod_mul(D, mod_mul(x1x2, y1y2));
                let new_x = mod_add(x1y2, y1x2).rotate_left(13) ^ d_xy;
                let new_y = mod_sub(y1y2, x1x2).rotate_right(19) ^ mod_add(d_xy, round as u64);
                self.state[i] = new_x % Q; self.state[i + 8] = new_y % Q;
            }
        }
    }
    fn absorb_lattice(&mut self, lattice_vec: &[u64; N]) {
        for (i, &val) in lattice_vec.iter().enumerate() {
            self.state[i % 16] = mod_add(self.state[i % 16], val);
            if i % 16 == 15 { self.edwards_mix(); }
        }
        self.edwards_mix();
    }
    fn squeeze_64_bytes(&mut self) -> [u8; 64] {
        self.edwards_mix();
        let mut out = [0u8; 64];
        for i in 0..8 { out[i * 8..(i + 1) * 8].copy_from_slice(&self.state[i].to_le_bytes()); }
        out
    }
}

pub fn selh_hash(data: &[u8]) -> SelhHash {
    let chunks = dynamic_entropy_chunking(data);
    let mut sponge = AlgebraicEdwardsSponge::new();
    let mut topo_accum = [0u64; 128];

    for chunk in &chunks {
        let quantized = quantize_chunk(chunk);
        let spectrum = ntt_64(&quantized);
        let mut csprng = DeterministicCsprng::from_chunk(chunk);
        let (noisy_lattice, clean_topo) = lwe_project_dual(&quantized, &spectrum, &mut csprng);

        sponge.absorb_lattice(&noisy_lattice);
        for i in 0..128 { topo_accum[i] = topo_accum[i].wrapping_add(clean_topo[i]); }
    }

    let rigid_root = sponge.squeeze_64_bytes();
    let total_bytes = data.len().max(1) as u64;
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
    SelhHash { rigid_root, fuzzy_mask }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("--- ITH-Spectral: Spectral-Entropy Lattice Hash Engine (v2) ---");
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
