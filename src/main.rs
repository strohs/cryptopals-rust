#![allow(dead_code)]

use std::fs::File;
use std::io::{BufRead, BufReader};

use base64;
use cryptopals::{
    break_single_byte_xor, decrypt_repeating_xor, encrypt_repeating_xor, fixed_xor, hamming,
    hex_decode, quadgram_score, to_string,
};

fn main() {
    break_repeating_key_xor();
}

/// set 1, challenge 1 - Convert Hex to Base64
fn s1_c1_convert_hex_to_base64(hex: &str) -> String {
    let bytes = hex_decode(hex);
    return base64::encode(&bytes);
}

/// set 1, challlenge 2 - FixedXOR
/// takes two equal length byte buffers and produces their XOR combination.
fn s1_c2_fixed_xor(buf1: &[u8], buf2: &[u8]) -> Vec<u8> {
    fixed_xor(buf1, buf2)
}

/// set 1, challenge 3 - Single Byte XOR cipher
/// `s` is a hex_encoded string to decrypt
fn s1_c3_single_byte_xor_cipher(s: &str) -> String {
    let bytes = hex_decode(s);
    let enc_byte =
        break_single_byte_xor(&bytes).expect("decrypted string is valid english plaintext");
    let decrypted: Vec<u8> = bytes.iter().map(|b| *b ^ enc_byte).collect();
    String::from_utf8(decrypted).expect("decrypted bytes are valid UTF-8")
}

/// set 1, challenge 4, detect single character XOR
/// returns the decrypted plaintext
fn s1_c4_detect_single_char_xor() -> String {
    let f = File::open("./files/4.txt").expect("able to find file at path");
    let f = BufReader::new(f);
    let mut scores: Vec<(char, f64, Vec<u8>)> = vec![];

    for (_line_num, line) in f.lines().enumerate() {
        let line = line.unwrap();
        let bytes = hex_decode(&line);

        for c in 0..=255 {
            let single_bytes = vec![c; bytes.len()];
            let xored = fixed_xor(&bytes, &single_bytes);
            if let Some(score) = quadgram_score(&xored) {
                scores.push((c as char, score, xored));
            }
        }
    }
    // sort scores in ascending order
    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    println!(
        "char '{}' had with best quadgram score of: {}",
        scores[0].0, scores[0].1
    );
    to_string(&scores[0].2)
}

/// set 1, challenge 5
/// returns an encrypted string using repeating key XOR with the key = 'ICE'
fn s1_c5_implement_repeating_xor() -> String {
    let s1 = r"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    let key = "ICE";
    let encrypted = encrypt_repeating_xor(&s1, &key);
    encrypted
}

/// set 1 challenge 6
fn break_repeating_key_xor() {
    let xored = std::fs::read("./files/6_decoded.txt").expect("able to find file");

    // step 1, guess the encryption keysize. Try sizes between 2..=40
    //  Compare FIRST and SECOND keysize worth of bytes, find hamming distance between them and
    //  normalize result by dividing by keysize
    // The keysize with the smallest normalized edit distance is probably the key
    let probable_keys = {
        let mut sizes: Vec<(u64, f64)> = vec![];
        for keysize in 2_u64..=40 {
            let chunks: Vec<&[u8]> = xored.chunks_exact(keysize as usize).take(4).collect();
            let d1 = hamming(chunks[0], chunks[1]) as f64 / keysize as f64;
            let d2 = hamming(chunks[1], chunks[2]) as f64 / keysize as f64;
            let d3 = hamming(chunks[2], chunks[3]) as f64 / keysize as f64;
            let normalized = (d1 + d2 + d3) / 3.0;
            //println!("{:2}: {:8.4} {:8.4} {:8.4}   avg:{:8.4}", keysize, d1, d2, d3, normalized);
            sizes.push((keysize, normalized));
        }
        sizes.sort_unstable_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        sizes
    };

    // use the top 3 probable keys with the lowest scores
    let keysizes: Vec<u64> = probable_keys.into_iter().map(|r| r.0).take(3).collect();

    // For each keysize, we need to partition the Xored bytes into N blocks, where N is the
    // current KEYSIZE. Each of those blocks must contain corresponding bytes. For Example:
    // Suppose the current KEYSIZE is 3 and our xored bytes = [0, 1, 2, 3, 4, 5, 6, 7, 8],
    // we need to build "byte_blocks" that look like: [[0,3,6], [1,4,7], [2,5,8]]. We can then
    // then try to guess the single byte cipher for each of those byte blocks, and use the best
    // scoring byte for each block the construct the final repeating key.

    let mut final_keys: Vec<Vec<u8>> = Vec::new();
    for keysize in keysizes {
        let mut byte_blocks: Vec<Vec<u8>> = Vec::new();
        for k in 0..keysize as usize {
            let block: Vec<u8> = xored[k..]
                .iter()
                .step_by(keysize as usize)
                .cloned()
                .collect();
            byte_blocks.push(block);
        }
        // key holds the best scoring byte for each byte block
        let mut key: Vec<u8> = vec![];
        for (i, block) in byte_blocks.iter().enumerate() {
            // try to guess the key using single byte xor
            let k = break_single_byte_xor(block);
            if let Some(key_byte) = k {
                println!(
                    "  adding byte {}({}) for keysize {} block {}",
                    key_byte, key_byte as char, keysize, i
                );
                key.push(key_byte);
            }
        }
        if !key.is_empty() {
            final_keys.push(key);
        }
    }
    // try to decrypt using each final key, print the plaintext to stdout
    // The actual key is: Terminator X: Bring the noise
    for key in &final_keys {
        let s = String::from_utf8(key.clone()).expect("valid bytes in key");
        println!("decrypting with key: {}({})", s, key.len());
        println!("----------------------------------------------------------------");
        let decrypted = decrypt_repeating_xor(&xored, &key);
        println!(
            "{}",
            String::from_utf8(decrypted).expect("valid ASCII bytes")
        );
        println!("----------------------------------------------------------------");
    }
}

#[cfg(test)]
mod test {
    use super::{
        s1_c1_convert_hex_to_base64, s1_c2_fixed_xor, s1_c3_single_byte_xor_cipher,
        s1_c4_detect_single_char_xor, s1_c5_implement_repeating_xor,
    };
    use cryptopals::{hex_decode, hex_encode};

    #[test]
    fn test_hex_to_base64() {
        assert_eq!(s1_c1_convert_hex_to_base64(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
                   "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
    }

    #[test]
    fn test_fixed_xor() {
        let s1 = hex_decode("1c0111001f010100061a024b53535009181c");
        let s2 = hex_decode("686974207468652062756c6c277320657965");
        let xored = s1_c2_fixed_xor(&s1, &s2);
        assert_eq!(hex_encode(&xored), "746865206b696420646f6e277420706c6179");
    }

    #[test]
    fn test_s1_c3() {
        let s = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let decoded = s1_c3_single_byte_xor_cipher(s);
        assert_eq!(decoded, "Cooking MC's like a pound of bacon");
    }

    #[test]
    fn test_s1_c4() {
        let decrypted = s1_c4_detect_single_char_xor();
        assert_eq!(decrypted, "Now that the party is jumping\n");
    }

    #[test]
    fn test_s1_c5() {
        assert_eq!(s1_c5_implement_repeating_xor(), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    }
}
