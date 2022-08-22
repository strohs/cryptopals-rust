// use std::collections::HashMap;
//
// // NOTE this Base64 implementation is Bugged. Use the "base64" crate instead
//
// lazy_static! {
//
//     /// maps the Base64 decimal index to the byte value of an ASCII character
//     static ref BASE64_ASCII: HashMap<u8, u8> = {
//         let mut base64 = HashMap::new();
//         for (i, c) in ('A'..='Z').chain(('a'..='z').chain('0'..='9')).enumerate() {
//             base64.insert(i as u8, c as u8);
//         }
//         base64.insert(62, b'+');
//         base64.insert(63, b'/');
//         base64
//     };
//     // ascii '=' is 61 decimal
// }
//
// /// decodes the bytes of a Base64 encoded string back into a vector of ASCII bytes
// pub fn decode(bytes: &[u8]) -> Vec<u8> {
//     // 4 base64 bytes are typically converted to three bytes, (or 6 hex characters)
//     let mut decoded: Vec<u8> = Vec::new();
//     for chunk in bytes.chunks(4) {
//         // bits holds unpacked base64 bytes
//         let mut bits = 0_u32;
//         for byte in chunk {
//             bits <<= 6;
//             bits = bits | ((*byte & 63) as u32);
//         }
//
//         match chunk.len() {
//             // two b64 bytes decode to 1 byte
//             2 => {
//                 decoded.push((bits >> 4 & 0x000000FF) as u8);
//             }
//             // three b64 bytes decode to 2 bytes
//             3 => {
//                 bits >>= 2;
//                 decoded.push(((bits & 0x0000FF00) >> 8) as u8);
//                 decoded.push((bits & 0x000000FF) as u8);
//             }
//             // all four b64 bytes decode to 3 bytes
//             4 => {
//                 decoded.push(((bits & 0x00FF0000) >> 16) as u8);
//                 decoded.push(((bits & 0x0000FF00) >> 8) as u8);
//                 decoded.push((bits & 0x000000FF) as u8);
//             }
//             len => panic!("invalid chunk count {} during decode", len),
//         }
//     }
//     decoded
// }
//
// /// encode a slice of bytes into Base64
// /// returns the bytes of the Base64 encoded characters
// pub fn encode(bytes: &[u8]) -> Vec<u8> {
//     let mut encoded: Vec<u8> = Vec::new();
//
//     // try to grab, at most, 24-bit chunks
//     for chunk in bytes.chunks(3) {
//         let packed = pack_hex_bytes(chunk);
//         match chunk.len() {
//             3 => {
//                 encoded.push((packed >> 18 & 63) as u8);
//                 encoded.push((packed >> 12 & 63) as u8);
//                 encoded.push((packed >> 6 & 63) as u8);
//                 encoded.push((packed & 63) as u8);
//             }
//             2 => {
//                 encoded.push((packed >> 10 & 63) as u8);
//                 encoded.push((packed >> 4 & 63) as u8);
//                 encoded.push((packed << 2 & 63) as u8);
//             }
//             1 => {
//                 encoded.push((packed >> 2 & 63) as u8);
//                 encoded.push((packed << 4 & 63) as u8);
//             }
//             _ => panic!("chunk size must by 3, 2, or 1, got {}", chunk.len()),
//         }
//     }
//     encoded
// }
//
// /// converts Base64 encoded bytes into their String representation
// pub fn to_string(bytes: &[u8]) -> String {
//     let ascii_bytes: Vec<u8> = bytes
//         .iter()
//         .map(|b| {
//             BASE64_ASCII
//                 .get(b)
//                 .expect("valid mapping for base64 byte index")
//         })
//         .cloned()
//         .collect();
//     let ascii_str =
//         String::from_utf8(ascii_bytes).expect("ascii bytes should be valid utf8 byte");
//     ascii_str
// }
//
//
// /// convert a slice of ASCII hex bytes into a 24-bit, packed, u32
// /// returns a u32, but only the first 24 least significant bits will contain the packed number
// fn pack_hex_bytes(bytes: &[u8]) -> u32 {
//     let mut packed = 0_u32;
//     if bytes.len() > 3 {
//         panic!("hex bytes must not exceed 3 bytes");
//     }
//     for b in bytes {
//         packed = packed << 8 | *b as u32
//     }
//     packed
// }
//
// #[cfg(test)]
// mod tests {
//     use crate::base64::{decode, encode, to_string};
//
//     #[test]
//     fn base64_encode_three_bytes() {
//         let text = b"Man".to_vec();
//         let b64 = encode(&text);
//         // should have 4 base64 'characters'
//         assert_eq!(b64.len(), 4);
//         assert_eq!(b64[0], 19); // Base64 T
//         assert_eq!(b64[1], 22); // Base64 W
//         assert_eq!(b64[2], 5); // Base64 F
//         assert_eq!(b64[3], 46); // Base64 u
//     }
//
//     #[test]
//     fn base64_encode_two_bytes() {
//         let text = b"Ma".to_vec();
//         let b64 = encode(&text);
//         // should have 4 base64 'characters'
//         assert_eq!(b64.len(), 3);
//         assert_eq!(b64[0], 19); // Base64 T
//         assert_eq!(b64[1], 22); // Base64 W
//         assert_eq!(b64[2], 4); // Base64 E
//     }
//
//     #[test]
//     fn base64_encode_one_byte() {
//         let text = b"M".to_vec();
//         let b64 = encode(&text);
//         // should have 4 base64 'characters'
//         assert_eq!(b64.len(), 2);
//         assert_eq!(b64[0], 19); // Base64 T
//         assert_eq!(b64[1], 16); // Base64 Q
//     }
//
//     #[test]
//     fn base64_display() {
//         let text = b"Man".to_vec();
//         let b64 = encode(&text);
//         assert_eq!(to_string(&b64), "TWFu");
//     }
//
//     #[test]
//     fn decode_four_base64_chars() {
//         let text = b"Man".to_vec();
//         let b64 = encode(&text); // TWFu
//         let decoded = decode(&b64);
//         assert_eq!(decoded[0], b'M');
//         assert_eq!(decoded[1], b'a');
//         assert_eq!(decoded[2], b'n');
//     }
//
//     #[test]
//     fn decode_three_base64_chars() {
//         let text = b"Ma".to_vec();
//         let b64 = encode(&text); // TWE
//         let decoded = decode(&b64);
//         assert_eq!(decoded[0], b'M');
//         assert_eq!(decoded[1], b'a');
//     }
//
//     #[test]
//     fn decode_one_base64_char() {
//         let text = b"M".to_vec();
//         let b64 = encode(&text); // TQ
//         let decoded = decode(&b64);
//         assert_eq!(decoded[0], b'M');
//     }
// }
