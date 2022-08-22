#[macro_use]
extern crate lazy_static;
use std::collections::HashMap;
use std::fmt::Write;
use std::fs::File;
use std::io::{BufRead, BufReader};

lazy_static! {
    /// frequencies of english letters in texts
    pub static ref FREQUENCIES: HashMap<u8, f64> = {
        let mut freqs = HashMap::new();
        freqs.insert(b'a', 0.08167);
        freqs.insert(b'b', 0.01492);
        freqs.insert(b'c', 0.02782);
        freqs.insert(b'd', 0.04253);
        freqs.insert(b'e', 0.12702);
        freqs.insert(b'f', 0.02228);
        freqs.insert(b'g', 0.02015);
        freqs.insert(b'h', 0.06094);
        freqs.insert(b'i', 0.06966);
        freqs.insert(b'j', 0.00153);
        freqs.insert(b'k', 0.00772);
        freqs.insert(b'l', 0.04025);
        freqs.insert(b'm', 0.02406);
        freqs.insert(b'n', 0.06749);
        freqs.insert(b'o', 0.07507);
        freqs.insert(b'p', 0.01929);
        freqs.insert(b'q', 0.00095);
        freqs.insert(b'r', 0.05987);
        freqs.insert(b's', 0.06327);
        freqs.insert(b't', 0.09056);
        freqs.insert(b'u', 0.02758);
        freqs.insert(b'v', 0.00978);
        freqs.insert(b'w', 0.02360);
        freqs.insert(b'x', 0.00150);
        freqs.insert(b'y', 0.01974);
        freqs.insert(b'z', 0.00074);
        freqs
    };
}

// sum of all the quad counts from the file english_quadgrams.txt
const TOTAL_QUAD_COUNT: f64 = 4224127912.0;

lazy_static! {
    // english_QuadGrams.txt maps 4 character quads to the number of times they occur in
    //   english texts, it contains 389373 quads.

    // maps a quad-gram bytes to its probability of occurring in english, as a logarithmic probability
    pub static ref QUADGRAM_PROBS: HashMap<[u8; 4], f64> = {
        let mut m = HashMap::new();
        let f = File::open("./files/english_quadgrams.txt").expect("can find quadgram file");
        for l in BufReader::new(f).lines() {
            let line = l.unwrap();
            let split: Vec<&str> = line.split(" ").collect();
            let quad = split[0].to_string().to_lowercase();
            let quad_bytes: [u8; 4] = quad.into_bytes().try_into().expect("can convert quad string to byte array");
            let quad_count = u32::from_str_radix(split[1], 10).expect("valid u32 number");
            let prob = (quad_count as f64 / TOTAL_QUAD_COUNT).log10();
            m.insert(quad_bytes, prob);
        }
        m
    };

}

/// criteria for a byte to be considered a valid english character in these challenges
fn valid_english_byte(b: &u8) -> bool {
    b.is_ascii_alphanumeric() || b.is_ascii_punctuation() || matches!(*b, 10 | 32)
}

/// use chi squared testing to see if the input bytes `bytes`, which are valid ASCII bytes,
/// resemble english plaintext.
///
/// Lower scores indicate a better likelihood of being english
///
/// Returns `None` if there is no possible way for `bytes` to be english text else
/// `Some(f64)` if there is a chance that the bytes are english text
pub fn chi2_score(bytes: &[u8]) -> Option<f64> {
    if !bytes.iter().all(|b| valid_english_byte(b)) {
        return None;
    }
    // should be at least one space, but ideally some amount based on the total length of bytes
    if !bytes.iter().any(|b| *b == 32) {
        return None;
    }
    // build a frequency map of only the letters within bytes
    let frequencies: HashMap<u8, u64> =
        bytes
            .iter()
            .filter(|b| b.is_ascii_alphabetic())
            .fold(HashMap::new(), |mut hm, b| {
                *hm.entry(b.to_ascii_lowercase()).or_insert(0) += 1;
                hm
            });

    let total_letters: u64 = frequencies.values().sum();
    if total_letters == 0 {
        return None;
    }

    // compute the chi squared
    let mut score = 0_f64;
    for letter in frequencies.keys() {
        let count = *frequencies.get(letter).unwrap() as f64;
        let expected = (total_letters as f64) * *FREQUENCIES.get(letter).unwrap();
        score += (count - expected).powi(2) / expected;
    }

    Some(score)
}

/// given a block of XOR encrypted bytes, try to find the single byte that
/// decrypts the entire block into english text.
/// returns `Some(u8)` containing the byte value of the character that decrypted the block into
/// english plaintext.
/// return `None` if the block could not be decrypted because the scoring algorithm did not
/// recognize it as english
pub fn break_single_byte_xor(block: &[u8]) -> Option<u8> {
    type Score = Vec<(u8, f64, Vec<u8>)>;
    let mut scores: Score = vec![];
    for c in 0..=255 {
        let single_bytes = vec![c; block.len()];
        let xored = fixed_xor(&block, &single_bytes);
        if let Some(score) = chi2_score(&xored) {
            println!(
                "  trying  {}({}) {:7.4} ||{}||",
                c,
                c as char,
                score,
                to_string(&xored)
            );
            scores.push((c, score, xored));
        }
    }
    // sort ascending, want lower score
    scores.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    // uncomment to debug top 3 scores
    // for score in scores.iter().take(3) {
    //     let db = String::from_utf8(score.2.clone()).expect("valid ascii bytes");
    //     println!("   top3 {}({})  {:10.3}  {}", score.0, score.0 as char, score.1, db);
    // }

    // return the best score
    scores.get(0).map(|score| score.0)
}

/// decode a hex str into a vector of bytes
pub fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

/// encode the given bytes into a lowercase hexadecimal string.
/// Each hex byte will be zero padded
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::new();
    for b in bytes {
        write!(&mut encoded, "{:02x}", *b).expect("byte can be converted to hex");
    }
    encoded
}

/// XOR corresponding bytes in buf1 and buf2
/// returns a new Vec containing the XORed bytes
pub fn fixed_xor(buf1: &[u8], buf2: &[u8]) -> Vec<u8> {
    (0..buf1.len())
        .into_iter()
        .map(|i| buf1[i] ^ buf2[i])
        .collect::<Vec<u8>>()
}

/// builds a string from a vector of bytes, expects the bytes to be valid ASCII.
/// panics if a byte is not in range 0 to 255
pub fn to_string(bytes: &Vec<u8>) -> String {
    let mut string = String::new();
    for b in bytes {
        if !matches!(*b, 0..=255) {
            panic!("expected byte {} to be valid ASCII", *b);
        }
        string.push(*b as char);
    }
    string
}

/// encrypt the string slice `s` with the given `key`, using repeating XOR encryption.
/// returns the encrypted String as hexadecimal characters
pub fn encrypt_repeating_xor(s: &str, key: &str) -> String {
    let encrypted: Vec<u8> = s
        .bytes()
        .zip(key.bytes().cycle())
        .map(|(b1, b2)| b1 ^ b2)
        .collect();
    hex_encode(&encrypted)
}

/// decrypt the given `bytes` using the repeating `key`
/// returns a Vector with the decrypted bytes
pub fn decrypt_repeating_xor(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .zip(key.iter().cycle())
        .map(|(b1, b2)| *b1 ^ *b2)
        .collect()
}

/// returns the total number of bits that differ between corresponding bytes of `b1` and `b2`
/// panics if b1 and b2 are not the same length
pub fn hamming(buf1: &[u8], buf2: &[u8]) -> u64 {
    if buf1.len() != buf2.len() {
        panic!(
            "hamming distance strings are not equal length: {} != {}",
            buf1.len(),
            buf2.len()
        );
    }

    let mut count: u64 = 0;
    for (b1, b2) in buf1.iter().zip(buf2.iter()) {
        let mut xor = *b1 ^ *b2;
        while xor > 0 {
            xor &= xor - 1;
            count += 1;
        }
    }
    count
}

/// determine if the given bytes are english text using a quad-gram comparison method.
/// higher scores indicate a better likely hood of being english text
/// A score >= 0 is not english at all
pub fn quadgram_score(bytes: &[u8]) -> Option<f64> {
    // all bytes should be in alphabetic, numeric, or punctuation, LF, CR !matches!(*b, 10 | 13 | 32..=127)
    if bytes.iter().any(|b| !matches!(*b, 10 | 13 | 32..=127)) {
        return None;
    }
    // should be at least one space, but ideally some amount based on the total length of bytes
    if bytes.iter().filter(|b| **b == 32).count() == 0 {
        return None;
    }

    // only use lower case letters
    let letters: Vec<u8> = bytes
        .iter()
        .filter(|&b| b.is_ascii_alphabetic())
        .map(|b| b.to_ascii_lowercase())
        .collect();

    // majority of characters in bytes must be letters, try 50%
    if (letters.len() as f64) < (bytes.len() as f64 * 0.5) {
        return None;
    }

    // partition the letters into quadgrams and compute the probabilities
    let prob = letters.windows(4).fold(0_f64, |mut prob, quad| {
        if QUADGRAM_PROBS.contains_key(quad) {
            prob += *QUADGRAM_PROBS
                .get(quad)
                .expect("quadgram must be in the map");
        } else {
            prob += (0.01 / TOTAL_QUAD_COUNT).log10();
        }
        prob
    });

    Some(prob)
}

#[cfg(test)]
mod tests {
    use crate::{chi2_score, hamming, hex_decode, hex_encode, quadgram_score};

    #[test]
    fn hamming1() {
        let buf1 = b"this is a test";
        let buf2 = b"wokka wokka!!!";
        assert_eq!(hamming(buf1, buf2), 37);
    }

    #[test]
    fn hamming2() {
        let buf1 = [65_u8]; // 1000001
        let buf2 = [45_u8]; // 0101101
        assert_eq!(hamming(&buf1, &buf2), 4);
    }

    #[test]
    fn test_hex_encode() {
        let bytes = b"light wor";
        let encoded = hex_encode(bytes);
        assert_eq!(encoded, "6c6967687420776f72");
    }

    #[test]
    fn test_hex_decode() {
        assert_eq!(hex_decode("6c6967687420776f72"), b"light wor");
    }

    #[test]
    fn test_chi_squared() {
        let bytes = b"ATTACK THE EAST WALL OF THE CASTLE AT DAWN";
        let bytes2 = b"FYYFHP YMJ JFXY BFQQ TK YMJ HFXYQJ FY IFBS";
        let score = chi2_score(bytes).unwrap();
        let score2 = chi2_score(bytes2).unwrap();
        assert_eq!(format!("{:.3}", score), "20.322");
        assert_eq!(format!("{:.3}", score2), "769.066");
    }

    #[test]
    fn test_quad_score() {
        let bytes = b"ATTACK THE EAST WALL OF THE CASTLE AT DAWN";
        assert_eq!(quadgram_score(bytes), Some(-127.77224079273714));

        let bytes2 = b"FYYFHP YMJ JFXY BFQQ TK YMJ HFXYQJ FY IFBS";
        assert_eq!(quadgram_score(bytes2), Some(-302.3543701340869));

        let bytes3 = b"123456789 129384950\n\n";
        assert_eq!(quadgram_score(bytes3), None);
    }
}
