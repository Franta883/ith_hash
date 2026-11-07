use std::env;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

const STATE_WORDS: usize = 25; // 1600 bits total state (25 * 64-bit words)
const CHUNK_SIZE_1MB: usize = 1_048_576; // 1 MB fixed leaf chunk size

const COLOR_RESET: &str = "\x1b[0m";
const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_RED: &str = "\x1b[31m";

#[derive(Clone, Copy, Debug)]
pub struct SpongeConfig {
    pub capacity_bits: usize,
    pub rate_words: usize,
    pub block_size_bytes: usize,
}

impl SpongeConfig {
    /// Standard Mode: c = 1024 bits, r = 576 bits (9 words / 72 bytes)
    pub fn standard() -> Self {
        Self {
            capacity_bits: 1024,
            rate_words: 9,
            block_size_bytes: 72,
        }
    }

    /// Boosted Capacity Mode (/boostc): c = 1536 bits, r = 64 bits (1 word / 8 bytes)
    pub fn boosted() -> Self {
        Self {
            capacity_bits: 1536,
            rate_words: 1,
            block_size_bytes: 8,
        }
    }
}

// ========================================================================
//  Core Permutation Matrix f (v2.1.0 Architecture)
// ========================================================================
fn permute_state(state: &mut [u64; STATE_WORDS]) {
    let rho_constants: [u32; 25] = [
        0,  1,  62, 28, 27,
        36, 44, 6,  55, 20,
        3,  10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2,  61, 56, 14,
    ];

    for round in 1..=24u32 {
        // 1. Bijective Theta Layer
        let mut c_parity = [0u64; 5];
        for i in 0..5 {
            c_parity[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }
        for i in 0..5 {
            let m_mix = c_parity[(i + 4) % 5] ^ c_parity[(i + 1) % 5].rotate_left(1);
            for j in 0..5 {
                state[i + j * 5] ^= m_mix;
            }
        }

        // 2. Rho Diffusion & Pi Shuffle Layer
        let mut advanced_state = [0u64; STATE_WORDS];
        for i in 0..STATE_WORDS {
            let target_index = (i * 7) % STATE_WORDS;
            advanced_state[target_index] = state[i].rotate_left(rho_constants[i]);
        }
        *state = advanced_state;

        // 3. Non-Linear Quadratic Chi Layer
        let mut chi_state = [0u64; STATE_WORDS];
        for i in 0..STATE_WORDS {
            let s1 = state[(i + 1) % STATE_WORDS];
            let s2 = state[(i + 2) % STATE_WORDS];
            chi_state[i] = state[i] ^ ((!s1) & s2);
        }
        *state = chi_state;

        // 4. Asymmetrical Round Constant Injection
        let r = round as u64;
        let base_constant = 0x9e3779b97f4a7c15u64.rotate_left(round) ^ (r << 48) ^ (!r);
        for i in 0..STATE_WORDS {
            let unique_word_salt = (i as u64)
                .wrapping_mul(0xbf58476d1ce4e5b9u64)
                .rotate_left(i as u32);
            state[i] ^= base_constant ^ unique_word_salt;
        }
    }
}

// ========================================================================
//  Dynamic Sponge Absorption & Squeezing Engine
// ========================================================================
fn absorb_block(state: &mut [u64; STATE_WORDS], block: &[u8], rate_words: usize) {
    for i in 0..rate_words {
        let start = i * 8;
        let mut word_bytes = [0u8; 8];
        word_bytes.copy_from_slice(&block[start..start + 8]);
        state[i] ^= u64::from_le_bytes(word_bytes);
    }
    permute_state(state);
}

fn sponge_hash(prefix: u8, payload: &[u8], config: SpongeConfig) -> [u8; 32] {
    let mut state: [u64; STATE_WORDS] = [0; STATE_WORDS];
    let block_size = config.block_size_bytes;
    let rate_words = config.rate_words;

    let mut data_idx = 0;
    let mut is_first_block = true;

    loop {
        let mut block_data = vec![0u8; block_size];
        let mut b_len = 0;

        if is_first_block {
            block_data[0] = prefix; // Domain separation byte (0x00 or 0x01)
            b_len += 1;
            is_first_block = false;
        }

        while b_len < block_size && data_idx < payload.len() {
            block_data[b_len] = payload[data_idx];
            b_len += 1;
            data_idx += 1;
        }

        // Full intermediate block
        if b_len == block_size && data_idx < payload.len() {
            absorb_block(&mut state, &block_data, rate_words);
        } else {
            // Final block(s) with pad10*1 padding
            let mut padded_block = vec![0u8; block_size];
            padded_block[..b_len].copy_from_slice(&block_data[..b_len]);
            padded_block[b_len] |= 0x01;

            if b_len < block_size - 1 {
                padded_block[block_size - 1] |= 0x80;
                absorb_block(&mut state, &padded_block, rate_words);
            } else {
                // b_len == block_size - 1 or b_len == block_size (Wait: if b_len == block_size, we need a new block)
                absorb_block(&mut state, &padded_block, rate_words);
                let mut final_block = vec![0u8; block_size];
                final_block[block_size - 1] |= 0x80;
                absorb_block(&mut state, &final_block, rate_words);
            }
            break;
        }
    }

    // Squeeze 32 bytes (256 bits) respecting the rate limit
    let mut out = [0u8; 32];
    let mut bytes_squeezed = 0;

    while bytes_squeezed < 32 {
        for i in 0..rate_words {
            if bytes_squeezed >= 32 {
                break;
            }
            let word_bytes = state[i].to_le_bytes();
            let copy_len = std::cmp::min(8, 32 - bytes_squeezed);
            out[bytes_squeezed..bytes_squeezed + copy_len].copy_from_slice(&word_bytes[..copy_len]);
            bytes_squeezed += copy_len;
        }
        if bytes_squeezed < 32 {
            permute_state(&mut state);
        }
    }

    out
}

// Note: Handles exact boundary when b_len == block_size at the end of payload
fn hash_with_domain(prefix: u8, payload: &[u8], config: SpongeConfig) -> [u8; 32] {
    let mut state: [u64; STATE_WORDS] = [0; STATE_WORDS];
    let block_size = config.block_size_bytes;
    let rate_words = config.rate_words;

    let mut data_idx = 0;
    let mut is_first_block = true;

    loop {
        let mut block_data = vec![0u8; block_size];
        let mut b_len = 0;

        if is_first_block {
            block_data[0] = prefix;
            b_len += 1;
            is_first_block = false;
        }

        while b_len < block_size && data_idx < payload.len() {
            block_data[b_len] = payload[data_idx];
            b_len += 1;
            data_idx += 1;
        }

        if b_len == block_size {
            // Absorb full rate block; loop continues to either read more payload or pad an empty block
            absorb_block(&mut state, &block_data, rate_words);
        } else {
            // b_len is strictly less than block_size, safe to place 0x01 padding bit
            block_data[b_len] |= 0x01;

            if b_len < block_size - 1 {
                block_data[block_size - 1] |= 0x80;
                absorb_block(&mut state, &block_data, rate_words);
            } else {
                absorb_block(&mut state, &block_data, rate_words);
                let mut final_block = vec![0u8; block_size];
                final_block[block_size - 1] |= 0x80;
                absorb_block(&mut state, &final_block, rate_words);
            }
            break;
        }
    }

    // Squeeze 32 bytes (4 words total)
    let mut out = [0u8; 32];
    let mut bytes_squeezed = 0;

    while bytes_squeezed < 32 {
        for i in 0..rate_words {
            if bytes_squeezed >= 32 {
                break;
            }
            let word_bytes = state[i].to_le_bytes();
            let copy_len = std::cmp::min(8, 32 - bytes_squeezed);
            out[bytes_squeezed..bytes_squeezed + copy_len].copy_from_slice(&word_bytes[..copy_len]);
            bytes_squeezed += copy_len;
        }
        if bytes_squeezed < 32 {
            permute_state(&mut state);
        }
    }

    out
}

// Low-level internal raw block ingestion hash engine (Domain Prefix 0x01)
fn hash_internal_node(
    prefix: u8,
    data1: &[u8; 32],
    data2: &[u8; 32],
    config: SpongeConfig,
) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(data1);
    combined[32..64].copy_from_slice(data2);
    hash_with_domain(prefix, &combined, config)
}

// Ingests raw leaf chunks data using domain prefix separation 0x00
fn hash_leaf_chunk(data: &[u8], config: SpongeConfig) -> [u8; 32] {
    hash_with_domain(0x00, data, config)
}

pub fn compute_merkle_tree_root<P: AsRef<Path>>(
    file_path: P,
    config: SpongeConfig,
) -> io::Result<String> {
    let file = File::open(&file_path)?;
    let file_size = file.metadata()?.len() as usize;

    if file_size == 0 {
        // Fallback for empty files: hash of single empty leaf block
        let empty_hash = hash_leaf_chunk(&[], config);
        return Ok(empty_hash.iter().map(|b| format!("{:02x}", b)).collect());
    }

    let num_chunks = (file_size + CHUNK_SIZE_1MB - 1) / CHUNK_SIZE_1MB;
    let leaves = Arc::new(Mutex::new(vec![[0u8; 32]; num_chunks]));
    let file_arc = Arc::new(Mutex::new(file));
    let mut workers = Vec::new();

    // PHASE 1: Multi-threaded parallel leaf allocation
    for chunk_idx in 0..num_chunks {
        let file_clone = Arc::clone(&file_arc);
        let leaves_clone = Arc::clone(&leaves);

        let handle = thread::spawn(move || {
            let mut local_buf = vec![0u8; CHUNK_SIZE_1MB];
            let bytes_read = {
                let mut f = file_clone.lock().unwrap();
                let _ = f.seek(SeekFrom::Start((chunk_idx * CHUNK_SIZE_1MB) as u64));
                f.read(&mut local_buf).unwrap_or(0)
            };
            let chunk_hash = hash_leaf_chunk(&local_buf[..bytes_read], config);
            let mut l = leaves_clone.lock().unwrap();
            l[chunk_idx] = chunk_hash;
        });
        workers.push(handle);
    }

    for worker in workers {
        let _ = worker.join();
    }

    // PHASE 2: Symmetrical Pairwise Reduction Tree Collapse
    let mut current_level = Arc::try_unwrap(leaves).unwrap().into_inner().unwrap();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
        let mut i = 0;

        while i < current_level.len() {
            if i + 1 < current_level.len() {
                // Symmetrical regular pair matching
                let node_hash =
                    hash_internal_node(0x01, &current_level[i], &current_level[i + 1], config);
                next_level.push(node_hash);
            } else {
                // Asymmetrical odd index matching: duplicate node with itself
                let node_hash =
                    hash_internal_node(0x01, &current_level[i], &current_level[i], config);
                next_level.push(node_hash);
            }
            i += 2;
        }
        current_level = next_level;
    }

    let root_bytes = current_level[0];
    Ok(root_bytes.iter().map(|b| format!("{:02x}", b)).collect())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("--- ITH-Tree: Parallel Merkle Tree Engine ---");
        println!("Usage:  ith_tree [/boostc] <file_path>");
        println!("Flags:");
        println!("  /boostc   Boost sponge capacity (c) from 1024 bits to 1536 bits (rate = 64 bits)");
        return;
    }

    let mut boost_c = false;
    let mut path_parts: Vec<&str> = Vec::new();

    for arg in &args[1..] {
        if arg.eq_ignore_ascii_case("/boostc") {
            boost_c = true;
        } else {
            path_parts.push(arg.as_str());
        }
    }

    if path_parts.is_empty() {
        eprintln!(
            "{}Error: No file path provided. Usage: ith_tree [/boostc] <file_path>{}",
            COLOR_RED, COLOR_RESET
        );
        std::process::exit(1);
    }

    let raw_path = path_parts.join(" ");
    let file_path = raw_path.trim_matches('"');

    if !Path::new(file_path).exists() {
        eprintln!(
            "{}Error: file not found: {}{}",
            COLOR_RED, file_path, COLOR_RESET
        );
        std::process::exit(1);
    }

    let config = if boost_c {
        eprintln!(
            "{}[Mode: Boosted Capacity | c = 1536 bits, r = 64 bits]{}",
            COLOR_GREEN, COLOR_RESET
        );
        SpongeConfig::boosted()
    } else {
        SpongeConfig::standard()
    };

    match compute_merkle_tree_root(file_path, config) {
        Ok(root_hash) => println!("{}", root_hash),
        Err(e) => eprintln!(
            "{}Error processing Merkle tree: {}{}",
            COLOR_RED, e, COLOR_RESET
        ),
    }
}