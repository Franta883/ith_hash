use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const COLOR_RESET: &str = "\x1b[0m";
const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_RED: &str = "\x1b[31m";

// A pre-computed, high-entropy random lookup matrix for Gear Hash (mapping 0..=255 to u64)
const GEAR_MATRIX: [u64; 256] = [
    0x192d24241ab7e57c, 0xef2688e100dc8dfa, 0x76251b5c46440b84, 0x6e8f4cb7cb95a315,
    0xf8da8d7cb27a206a, 0x2289c8a95610ec50, 0x93306c59d95be093, 0xcd6bbd1d575dfa8e,
    0x2b8004fcf189da59, 0xb8be3f3da33cf852, 0xe00d0bc5d9f0ab56, 0x61a7dc2eb76aa8a8,
    0x3ca2fa6b21bc0b53, 0x9e246cf7be7ff10a, 0x09da563d76eef5ee, 0xbe2b92a2a7cc33e1,
    0x401df4e43e5c949c, 0xb1b0f55fb9ef775a, 0x7d02b3dfbb910609, 0x8a9bf3df1c808f90,
    0x616cd4fc28b7eec9, 0xa19a9b1c7dc41c2d, 0x3d39ec5d36e2f171, 0x5b3f1c1f54cfadba,
    0xbef5e1dc7f30df00, 0x981eeefbe1a700da, 0xc19bb3ea1901cbcc, 0xbc3cbafca7aef00d,
    0x4f1b2dfce9cf2aef, 0xad5deecda9ea53ee, 0x99da1d2b8feeb4da, 0x4f3ce17f9daeb3de,
    0x1c3a6fec5af1a72d, 0xd00aa8fd5be9fca8, 0x1da5bb3dfc9fe0dd, 0xaa2dceef5ea2d8fb,
    0xb3c0eeefda2beea7, 0x5df3cecf5a2ce01d, 0x2d1ebcf3ef2ce10d, 0x7a2cefdc3be1ae7d,
    0x93ce3fa9dcbe76a1, 0x1fbe32dfcf20ef22, 0x4e6be31da9fbb3ae, 0xbc3defda9cb32ea9,
    0x96ef2cda9fb0eb3d, 0x7cf1dfa34ee9cae1, 0x3cf3ce5b1fce6ba1, 0x9ef1b3adbe9cf2de,
    0xdfbe3c1da0fed00a, 0x5ae3cd2be09cf2de, 0xfa3be20ca0be0fa2, 0x3be1cd9fa2be0eb1,
    0x19aef3bd7a0fbe2d, 0x6cf2de30afbe0cd1, 0x8fb3deac70fbe0d3, 0xf02be310adfe20fa,
    0x3be02da5be1c6ba1, 0xcbe310dfa30fe2de, 0x2be310ca7fe12fbe, 0x4be1cd2ae30fed1c,
    0x9ef310da7fe023be, 0x1be0ce2de0fbe210, 0xfce30f2ae10fbe3d, 0x9fe302be10adfe2c,
    0x40df21fbe03cb290, 0x6e2df10caef301be, 0x3be0cd1e20fe1dca, 0x19fe02ca2be0fed3,
    0xbc3be02da5fe1cd2, 0x7be201fbe02cd341, 0x4fe2da51be301cae, 0x3be1cd2ae3ef02be,
    0x9ef03ca2fe02d1ce, 0xbe3cd25be02fa10e, 0x3ce12dfae301fbe2, 0x9e2cd30afbe10ca2,
    0xfbe02da1fe301ce2, 0xbc3e120da5fe01cd, 0x4fe1cd20be3cf10a, 0x3be01ca2fbe02cd3,
    0x61a7dc2eb76aa8a8, 0x3ca2fa6b21bc0b53, 0x9e246cf7be7ff10a, 0x09da563d76eef5ee,
    0x401df4e43e5c949c, 0xb1b0f55fb9ef775a, 0x7d02b3dfbb910609, 0x8a9bf3df1c808f90,
    0x616cd4fc28b7eec9, 0xa19a9b1c7dc41c2d, 0x3d39ec5d36e2f171, 0x5b3f1c1f54cfadba,
    0xbef5e1dc7f30df00, 0x981eeefbe1a700da, 0xc19bb3ea1901cbcc, 0xbc3cbafca7aef00d,
    0xef2688e100dc8dfa, 0x76251b5c46440b84, 0x6e8f4cb7cb95a315, 0xf8da8d7cb27a206a,
    0x2289c8a95610ec50, 0x93306c59d95be093, 0xcd6bbd1d575dfa8e, 0x2b8004fcf189da59,
    0xb8be3f3da33cf852, 0xe00d0bc5d9f0ab56, 0x61a7dc2eb76aa8a8, 0x3ca2fa6b21bc0b53,
    0xd00aa8fd5be9fca8, 0x1da5bb3dfc9fe0dd, 0xaa2dceef5ea2d8fb, 0xb3c0eeefda2beea7,
    0x5df3cecf5a2ce01d, 0x2d1ebcf3ef2ce10d, 0x7a2cefdc3be1ae7d, 0x93ce3fa9dcbe76a1,
    0x1fbe32dfcf20ef22, 0x4e6be31da9fbb3ae, 0xbc3defda9cb32ea9, 0x96ef2cda9fb0eb3d,
    0xfa3be20ca0be0fa2, 0x3be1cd9fa2be0eb1, 0x19aef3bd7a0fbe2d, 0x6cf2de30afbe0cd1,
    0x8fb3deac70fbe0d3, 0xf02be310adfe20fa, 0x3be02da5be1c6ba1, 0xcbe310dfa30fe2de,
    0x2be310ca7fe12fbe, 0x4be1cd2ae30fed1c, 0x9ef310da7fe023be, 0x1be0ce2de0fbe210,
    0x40df21fbe03cb290, 0x6e2df10caef301be, 0x3be0cd1e20fe1dca, 0x19fe02ca2be0fed3,
    0xbc3be02da5fe1cd2, 0x7be201fbe02cd341, 0x4fe2da51be301cae, 0x3be1cd2ae3ef02be,
    0x9ef03ca2fe02d1ce, 0xbe3cd25be02fa10e, 0x3ce12dfae301fbe2, 0x9e2cd30afbe10ca2,
    0xfbe02da1fe301ce2, 0xbc3e120da5fe01cd, 0x4fe1cd20be3cf10a, 0x3be01ca2fbe02cd3,
    0x61a7dc2eb76aa8a8, 0x3ca2fa6b21bc0b53, 0x9e246cf7be7ff10a, 0x09da563d76eef5ee,
    0x401df4e43e5c949c, 0xb1b0f55fb9ef775a, 0x7d02b3dfbb910609, 0x8a9bf3df1c808f90,
    0x616cd4fc28b7eec9, 0xa19a9b1c7dc41c2d, 0x3d39ec5d36e2f171, 0x5b3f1c1f54cfadba,
    0xbef5e1dc7f30df00, 0x981eeefbe1a700da, 0xc19bb3ea1901cbcc, 0xbc3cbafca7aef00d,
    0xef2688e100dc8dfa, 0x76251b5c46440b84, 0x6e8f4cb7cb95a315, 0xf8da8d7cb27a206a,
    0x2289c8a95610ec50, 0x93306c59d95be093, 0xcd6bbd1d575dfa8e, 0x2b8004fcf189da59,
    0xb8be3f3da33cf852, 0xe00d0bc5d9f0ab56, 0x61a7dc2eb76aa8a8, 0x3ca2fa6b21bc0b53,
    0x2be310ca7fe12fbe, 0x4be1cd2ae30fed1c, 0x9ef310da7fe023be, 0x1be0ce2de0fbe210,
    0xfce30f2ae10fbe3d, 0x9fe302be10adfe2c, 0x40df21fbe03cb290, 0x6e2df10caef301be,
    0x3be0cd1e20fe1dca, 0x19fe02ca2be0fed3, 0xbc3be02da5fe1cd2, 0x7be201fbe02cd341,
    0x4fe2da51be301cae, 0x3be1cd2ae3ef02be, 0x9ef03ca2fe02d1ce, 0xbe3cd25be02fa10e,
    0x3ce12dfae301fbe2, 0x9e2cd30afbe10ca2, 0xfbe02da1fe301ce2, 0xbc3e120da5fe01cd,
    0x4fe1cd20be3cf10a, 0x3be01ca2fbe02cd3, 0x61a7dc2eb76aa8a8, 0x3ca2fa6b21bc0b53,
    0x9e246cf7be7ff10a, 0x09da563d76eef5ee, 0x401df4e43e5c949c, 0xb1b0f55fb9ef775a,
    0x7d02b3dfbb910609, 0x8a9bf3df1c808f90, 0x616cd4fc28b7eec9, 0xa19a9b1c7dc41c2d,
    0x3d39ec5d36e2f171, 0x5b3f1c1f54cfadba, 0xbef5e1dc7f30df00, 0x981eeefbe1a700da,
    0xc19bb3ea1901cbcc, 0xbc3cbafca7aef00d, 0xef2688e100dc8dfa, 0x76251b5c46440b84,
    0x6e8f4cb7cb95a315, 0xf8da8d7cb27a206a, 0x2289c8a95610ec50, 0x93306c59d95be093,
    0xcd6bbd1d575dfa8e, 0x2b8004fcf189da59, 0xb8be3f3da33cf852, 0xe00d0bc5d9f0ab56,
    0x61a7dc2eb76aa8a8, 0x3ca2fa6b21bc0b53, 0xd00aa8fd5be9fca8, 0x1da5bb3dfc9fe0dd,
    0xaa2dceef5ea2d8fb, 0xb3c0eeefda2beea7, 0x5df3cecf5a2ce01d, 0x2d1ebcf3ef2ce10d,
    0x7a2cefdc3be1ae7d, 0x93ce3fa9dcbe76a1, 0x1fbe32dfcf20ef22, 0x4e6be31da9fbb3ae,
    0xbc3defda9cb32ea9, 0x96ef2cda9fb0eb3d, 0xfa3be20ca0be0fa2, 0x3be1cd9fa2be0eb1,
];

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

// MODERNIZED: High-throughput Content-Defined Chunking via Gear Hash Engine
pub fn get_ctps_fuzzy_hash<P: AsRef<Path>>(file_path: P) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    if data.is_empty() {
        return Ok("4:A:A:0".to_string());
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

    // Gear Hash rolling state register
    let mut rolling_hash = 0u64;

    for i in 0..data.len() {
        let byte_val = data[i] as usize;

        // Gear rolling formula: Left shift and inject matrix mapping values
        rolling_hash = (rolling_hash << 1).wrapping_add(GEAR_MATRIX[byte_val]);

        // Evaluation Scale B
        if rolling_hash % (b as u64) == (b as u64) - 1 {
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
        if rolling_hash % (b2 as u64) == (b2 as u64) - 1 {
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
    for i in 0..=len1 { dp[i][0] = i; }
    for j in 0..=len2 { dp[0][j] = j; }
    for i in 1..=len1 {
        for j in 1..=len2 {
            if v1[i - 1] == v2[j - 1] { dp[i][j] = dp[i - 1][j - 1]; }
            else { dp[i][j] = 1 + dp[i - 1][j].min(dp[i][j - 1]).min(dp[i - 1][j - 1]); }
        }
    }
    dp[len1][len2]
}

// FIXED: Symmetrical multi-scale analysis using strict Rust syntax rules
pub fn compare_ctps_hashes(h1: &str, h2: &str) -> f64 {
    let p1: Vec<&str> = h1.split(':').collect();
    let p2: Vec<&str> = h2.split(':').collect();
    if p1.len() < 4 || p2.len() < 4 { return 0.0; }

    let b1: u32 = p1[0].parse().unwrap_or(0);
    let b2: u32 = p2[0].parse().unwrap_or(0);

    let (s1, s2) = if b1 == b2 {
        (p1[1], p2[1])
    } else if b1 == b2 * 2 {
        (p1[2], p2[1])
    } else if b2 == b1 * 2 {
        (p1[1], p2[2])
    } else {
        return 0.0;
    };
    
    let max_len = s1.len().max(s2.len());
    if max_len == 0 { return 100.0; }
    
    let dist = levenshtein_distance(s1, s2);
    let score = (1.0 - (dist as f64 / max_len as f64)) * 100.0;
    
    let e1 = p1[3];
    let e2 = p2[3];
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
    
    if args[1] == "/compare" || args[1] == "--compare" {
        if args.len() < 4 {
            eprintln!("{}Error: Two target hashes are required for comparison.{}", COLOR_RED, COLOR_RESET);
            std::process::exit(1);
        }
        let score = compare_ctps_hashes(&args[2], &args[3]);
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
