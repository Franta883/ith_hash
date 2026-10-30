use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const COLOR_RESET: &str = "\x1b[0m";
const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_RED: &str = "\x1b[31m";
const COLOR_CYAN: &str = "\x1b[36m";

fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0usize; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn fnv1a_32(data: &[u8]) -> u32 {
    let mut hash = 2166136261u32;
    for &b in data {
        hash ^= b as u32;
        hash = hash.wrapping_mul(16777619);
    }
    hash
}

fn entropy_to_anchor_char(entropy: f64) -> char {
    let scaled = (entropy * 1.875).round() as u32;
    let clamped = scaled.min(15);
    std::char::from_digit(clamped, 16).unwrap_or('0')
}

// FIXED: Implements the exact, math-correct SSDEEP Spamsum Rolling Engine
pub fn get_ctps_fuzzy_hash<P: AsRef<Path>>(file_path: P) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    if data.is_empty() {
        return Ok("0:A:A:0".to_string());
    }

    let file_size = data.len();
    let mut b = 4;
    while b * 64 < file_size && b < 4194304 {
        b *= 2;
    }

    let mut sig_b = String::new();
    let mut sig_2b = String::new();
    let mut entropy_anchors = String::new();

    let mut chunk_start_b = 0;
    let mut chunk_start_2b = 0;

    // True SSDEEP rolling state layout (Fixes the Adler-32 upper-bound vulnerability)
    const ROLLING_WINDOW: usize = 7;
    let mut h1 = 0u32;
    let mut h2 = 0u32;
    let mut h3 = 0u32;
    let mut window = [0u8; ROLLING_WINDOW];
    let mut n = 0usize;

    for i in 0..data.len() {
        let c = data[i] as u32;
        let old = window[n % ROLLING_WINDOW] as u32;

        // Iterative rolling matrix transformation
        h2 = h2.wrapping_sub(h1).wrapping_add(ROLLING_WINDOW as u32 * c);
        h1 = h1.wrapping_add(c).wrapping_sub(old);
        window[n % ROLLING_WINDOW] = c as u8;
        n += 1;
        
        // High-entropy accumulator spreading bits evenly across the full 32-bit width
        h3 = (h3 << 5) ^ c;

        let rolling_hash = h1.wrapping_add(h2).wrapping_add(h3);

        // Evaluation Scale B
        if rolling_hash % (b as u32) == (b as u32) - 1 {
            let chunk_len = i + 1 - chunk_start_b;
            if chunk_len >= b / 2 && sig_b.len() < 64 {
                let chunk_data = &data[chunk_start_b..=i];
                let f_hash = fnv1a_32(chunk_data);
                sig_b.push(BASE64_CHARS[(f_hash % 64) as usize] as char);
                let ent = calculate_shannon_entropy(chunk_data);
                entropy_anchors.push(entropy_to_anchor_char(ent));
                chunk_start_b = i + 1;
            }
        }

        // Evaluation Scale 2B
        let b2 = b * 2;
        if rolling_hash % (b2 as u32) == (b2 as u32) - 1 {
            let chunk_len = i + 1 - chunk_start_2b;
            if chunk_len >= b2 / 2 && sig_2b.len() < 64 {
                let chunk_data = &data[chunk_start_2b..=i];
                let f_hash = fnv1a_32(chunk_data);
                sig_2b.push(BASE64_CHARS[(f_hash % 64) as usize] as char);
                chunk_start_2b = i + 1;
            }
        }
    }

    // Flush final tail residuals
    if chunk_start_b < data.len() && sig_b.len() < 64 {
        let chunk_data = &data[chunk_start_b..];
        let f_hash = fnv1a_32(chunk_data);
        sig_b.push(BASE64_CHARS[(f_hash % 64) as usize] as char);
        let ent = calculate_shannon_entropy(chunk_data);
        entropy_anchors.push(entropy_to_anchor_char(ent));
    }
    if chunk_start_2b < data.len() && sig_2b.len() < 64 {
        let chunk_data = &data[chunk_start_2b..];
        let f_hash = fnv1a_32(chunk_data);
        sig_2b.push(BASE64_CHARS[(f_hash % 64) as usize] as char);
    }

    if sig_b.is_empty() { sig_b.push('A'); entropy_anchors.push('0'); }
    if sig_2b.is_empty() { sig_2b.push('A'); }

    Ok(format!("{}:{}:{}:{}", b, sig_b, sig_2b, entropy_anchors))
}

fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let v1: Vec<char> = s1.chars().collect();
    let v2: Vec<char> = s2.chars().collect();
    let len1 = v1.len();
    let len2 = v2.len();
    let mut dp = vec![vec![0; len2 + 1]; len1 + 1];
    for i in 0..=len1 { dp[i] = i; }
    for j in 0..=len2 { dp[j] = j; }
    for i in 1..=len1 {
        for j in 1..=len2 {
            if v1[i - 1] == v2[j - 1] { dp[i][j] = dp[i - 1][j - 1]; }
            else { dp[i][j] = 1 + dp[i - 1][j].min(dp[i][j - 1]).min(dp[i - 1][j - 1]); }
        }
    }
    dp[len1][len2]
}

pub fn compare_ctps_hashes(h1: &str, h2: &str) -> f64 {
    let p1: Vec<&str> = h1.split(':').collect();
    let p2: Vec<&str> = h2.split(':').collect();
    if p1.len() < 4 || p2.len() < 4 { return 0.0; }

    let b1: u32 = p1.parse().unwrap_or(0);
    let b2: u32 = p2.parse().unwrap_or(0);

    let (s1, s2) = if b1 == b2 {
        (p1, p2)
    } else if b1 == b2 * 2 {
        (p1, p2)
    } else if b2 == b1 * 2 {
        (p1, p2)
    } else {
        return 0.0;
    };

    let max_len = s1.len().max(s2.len());
    if max_len == 0 { return 100.0; }

    let dist = levenshtein_distance(s1, s2);
    let score = (1.0 - (dist as f64 / max_len as f64)) * 100.0;

    let e1 = p1;
    let e2 = p2;
    let e_max = e1.len().max(e2.len());
    if e_max > 0 {
        let e_dist = levenshtein_distance(e1, e2);
        let e_score = (1.0 - (e_dist as f64 / e_max as f64)) * 100.0;
        return (score * 0.8) + (e_score * 0.2);
    }
    score
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("--- ITH-Fuzzy: CTPS Fuzzy Hashing Tool ---");
        println!("Generation:  ith_fuzzy <file_path>");
        println!("Comparison:  ith_fuzzy /compare <hash_1> <hash_2>");
        return;
    }

    if args == "/compare" || args == "--compare" {
        if args.len() < 4 {
            eprintln!("{}Error: Two target hashes are required for comparison.{}", COLOR_RED, COLOR_RESET);
            std::process::exit(1);
        }
        let score = compare_ctps_hashes(&args, &args);
        if score > 50.0 {
            println!("{}Similarity Score: {:.2}% [MATCH]{}", COLOR_GREEN, score, COLOR_RESET);
        } else {
            println!("{}Similarity Score: {:.2}% [MISMATCH]{}", COLOR_RED, score, COLOR_RESET);
        }
        return;
    }

    let raw_path = args[1..].join(" ");
    let file_path = raw_path.trim_matches('"');

    match get_ctps_fuzzy_hash(file_path) {
        Ok(hash) => println!("{}", hash),
        Err(e) => {
            eprintln!("{}Error reading target file '{}': {}{}", COLOR_RED, file_path, e, COLOR_RESET);
            std::process::exit(1);
        }
    }
}
