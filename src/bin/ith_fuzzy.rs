use std::env;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const MAX_SIGNATURE_LEN: usize = 64;
const STREAM_BUF_SIZE: usize = 64 * 1024;

const COLOR_RESET: &str = "\x1b[0m";
const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_RED: &str = "\x1b[31m";

// Compile-time SplitMix64 generator using a "nothing-up-my-sleeve" golden ratio seed.
// Guarantees 256 unique, unbiased, high-entropy 64-bit integers.
const fn generate_gear_matrix() -> [u64; 256] {
    let mut matrix = [0u64; 256];
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut i = 0;
    while i < 256 {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        matrix[i] = z;
        i += 1;
    }
    matrix
}

const GEAR_MATRIX: [u64; 256] = generate_gear_matrix();

/// Incremental per-chunk state to support constant-memory streaming.
struct ChunkState {
    fnv_hash: u32,
    counts: [u64; 256],
    len: u64,
}

impl ChunkState {
    fn new() -> Self {
        Self {
            fnv_hash: 2_166_136_261u32,
            counts: [0u64; 256],
            len: 0,
        }
    }

    #[inline]
    fn update(&mut self, byte: u8) {
        self.fnv_hash ^= byte as u32;
        self.fnv_hash = self.fnv_hash.wrapping_mul(16_777_619);
        self.counts[byte as usize] += 1;
        self.len += 1;
    }

    fn reset(&mut self) {
        self.fnv_hash = 2_166_136_261u32;
        self.counts = [0u64; 256];
        self.len = 0;
    }

    /// Mixes all 32 bits via a MurmurHash3-style avalanche finalizer before
    /// XOR-folding into a 6-bit Base64 character index.
    fn finalize_base64_char(&self) -> char {
        let mut h = self.fnv_hash;
        h ^= h >> 16;
        h = h.wrapping_mul(0x85eb_ca6b);
        h ^= h >> 13;
        h = h.wrapping_mul(0xc2b2_ae35);
        h ^= h >> 16;

        let folded = (h ^ (h >> 6) ^ (h >> 12) ^ (h >> 18) ^ (h >> 24)) & 0x3F;
        BASE64_CHARS[folded as usize] as char
    }

    /// Computes Shannon entropy directly from the byte frequency table.
    fn finalize_entropy_char(&self) -> char {
        if self.len == 0 {
            return '0';
        }
        let total = self.len as f64;
        let mut entropy = 0.0;
        for &count in &self.counts {
            if count > 0 {
                let p = count as f64 / total;
                entropy -= p * p.log2();
            }
        }
        let scaled = (entropy * 1.875).round() as u32;
        let clamped = scaled.min(15);
        std::char::from_digit(clamped, 16).unwrap_or('0')
    }
}

pub fn get_ctps_fuzzy_hash<P: AsRef<Path>>(file_path: P) -> io::Result<String> {
    let file = File::open(file_path)?;
    let file_size = file.metadata()?.len();

    if file_size == 0 {
        return Ok("4:A:A:0:0".to_string());
    }

    let mut b: u64 = 4;
    while b * (MAX_SIGNATURE_LEN as u64) < file_size && b < 4_194_304 {
        b *= 2;
    }
    let b2 = b * 2;

    // Inspect the most significant bits of the 64-bit Gear rolling hash
    let shift_b = 64 - b.trailing_zeros();
    let mask_b = b - 1;
    let shift_2b = 64 - b2.trailing_zeros();
    let mask_2b = b2 - 1;

    let mut sig_b = String::with_capacity(MAX_SIGNATURE_LEN);
    let mut sig_2b = String::with_capacity(MAX_SIGNATURE_LEN);
    let mut ent_b = String::with_capacity(MAX_SIGNATURE_LEN);
    let mut ent_2b = String::with_capacity(MAX_SIGNATURE_LEN);

    let mut state_b = ChunkState::new();
    let mut state_2b = ChunkState::new();
    let mut rolling_hash = 0u64;

    let mut reader = BufReader::with_capacity(STREAM_BUF_SIZE, file);
    let mut buf = [0u8; STREAM_BUF_SIZE];

    loop {
        let bytes_read = reader.read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }

        for &byte in &buf[..bytes_read] {
            rolling_hash = (rolling_hash << 1).wrapping_add(GEAR_MATRIX[byte as usize]);
            state_b.update(byte);
            state_2b.update(byte);

            // Reserve the 64th slot (index 63) for the final tail flush so no suffix is dropped
            if (rolling_hash >> shift_b) == mask_b
                && state_b.len >= b / 2
                && sig_b.len() < MAX_SIGNATURE_LEN - 1
            {
                sig_b.push(state_b.finalize_base64_char());
                ent_b.push(state_b.finalize_entropy_char());
                state_b.reset();
            }

            if (rolling_hash >> shift_2b) == mask_2b
                && state_2b.len >= b2 / 2
                && sig_2b.len() < MAX_SIGNATURE_LEN - 1
            {
                sig_2b.push(state_2b.finalize_base64_char());
                ent_2b.push(state_2b.finalize_entropy_char());
                state_2b.reset();
            }
        }
    }

    // Flush remaining tail bytes into the final slot
    if state_b.len > 0 && sig_b.len() < MAX_SIGNATURE_LEN {
        sig_b.push(state_b.finalize_base64_char());
        ent_b.push(state_b.finalize_entropy_char());
    }
    if state_2b.len > 0 && sig_2b.len() < MAX_SIGNATURE_LEN {
        sig_2b.push(state_2b.finalize_base64_char());
        ent_2b.push(state_2b.finalize_entropy_char());
    }

    if sig_b.is_empty() {
        sig_b.push('A');
        ent_b.push('0');
    }
    if sig_2b.is_empty() {
        sig_2b.push('A');
        ent_2b.push('0');
    }

    Ok(format!("{}:{}:{}:{}:{}", b, sig_b, sig_2b, ent_b, ent_2b))
}

/// Space-optimized O(min(N, M)) Levenshtein distance capped at MAX_SIGNATURE_LEN.
fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let v1: Vec<char> = s1.chars().take(MAX_SIGNATURE_LEN).collect();
    let v2: Vec<char> = s2.chars().take(MAX_SIGNATURE_LEN).collect();
    let len1 = v1.len();
    let len2 = v2.len();

    let mut prev: Vec<usize> = (0..=len2).collect();
    let mut curr = vec![0usize; len2 + 1];

    for i in 1..=len1 {
        curr[0] = i;
        for j in 1..=len2 {
            let cost = if v1[i - 1] == v2[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1)
                .min(curr[j - 1] + 1)
                .min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[len2]
}

fn normalized_similarity(s1: &str, s2: &str) -> f64 {
    let len1 = s1.chars().take(MAX_SIGNATURE_LEN).count();
    let len2 = s2.chars().take(MAX_SIGNATURE_LEN).count();
    let max_len = len1.max(len2);
    if max_len == 0 {
        return 100.0;
    }
    let dist = levenshtein_distance(s1, s2);
    (1.0 - (dist as f64 / max_len as f64)) * 100.0
}

pub fn compare_ctps_hashes(h1: &str, h2: &str) -> f64 {
    let p1: Vec<&str> = h1.split(':').collect();
    let p2: Vec<&str> = h2.split(':').collect();
    if p1.len() < 4 || p2.len() < 4 {
        return 0.0;
    }

    let b1: u64 = match p1[0].parse::<u64>() {
        Ok(val) if val >= 4 && val.is_power_of_two() => val,
        _ => return 0.0,
    };
    let b2: u64 = match p2[0].parse::<u64>() {
        Ok(val) if val >= 4 && val.is_power_of_two() => val,
        _ => return 0.0,
    };

    // Align both chunk signatures AND entropy anchors to the exact same block scale
    let (s1, s2, e1_opt, e2_opt) = if b1 == b2 {
        (p1[1], p2[1], Some(p1[3]), Some(p2[3]))
    } else if b1 == b2 * 2 {
        // b1 matches 2 * b2: compare h1's scale-b against h2's scale-2b
        let e2 = p2.get(4).copied();
        (p1[1], p2[2], Some(p1[3]), e2)
    } else if b2 == b1 * 2 {
        // b2 matches 2 * b1: compare h1's scale-2b against h2's scale-b
        let e1 = p1.get(4).copied();
        (p1[2], p2[1], e1, Some(p2[3]))
    } else {
        return 0.0;
    };

    let sig_score = normalized_similarity(s1, s2);

    if let (Some(e1), Some(e2)) = (e1_opt, e2_opt) {
        if !e1.is_empty() && !e2.is_empty() {
            let ent_score = normalized_similarity(e1, e2);
            return (sig_score * 0.8) + (ent_score * 0.2);
        }
    }

    sig_score
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("--- ITH-Fuzzy: CTPS Fuzzy Hashing Tool ---");
        println!("Generation:  ith_fuzzy <file_path>");
        println!("Comparison:  ith_fuzzy /compare <hash_1> <hash_2>");
        return;
    }

    if args[1] == "/compare" || args[1] == "--compare" {
        if args.len() < 4 {
            eprintln!(
                "{}Error: Two target hashes are required for comparison.{}",
                COLOR_RED, COLOR_RESET
            );
            std::process::exit(1);
        }
        let score = compare_ctps_hashes(&args[2], &args[3]);
        if score > 50.0 {
            println!(
                "{}Similarity Score: {:.2}% [MATCH]{}",
                COLOR_GREEN, score, COLOR_RESET
            );
        } else {
            println!(
                "{}Similarity Score: {:.2}% [MISMATCH]{}",
                COLOR_RED, score, COLOR_RESET
            );
        }
        return;
    }

    let raw_path = args[1..].join(" ");
    let file_path = raw_path.trim_matches('"');

    match get_ctps_fuzzy_hash(file_path) {
        Ok(hash) => println!("{}", hash),
        Err(e) => {
            eprintln!(
                "{}Error reading target file '{}': {}{}",
                COLOR_RED, file_path, e, COLOR_RESET
            );
            std::process::exit(1);
        }
    }
}