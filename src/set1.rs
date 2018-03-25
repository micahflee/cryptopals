extern crate hex;
extern crate base64;
extern crate colored;

use std::str;
use std::collections::HashMap;
use colored::Colorize;

pub fn index() {
    println!("{}", "Challenge 1.1: Convert hex to base64".blue().bold());
    challenge1();

    println!("\n{}", "Challenge 1.2: Fixed XOR".blue().bold());
    challenge2();

    println!("\n{}", "Challenge 1.3: Single-byte XOR cipher".blue().bold());
    challenge3();
}

fn challenge1() {
    // https://cryptopals.com/sets/1/challenges/1
    let hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected_base64_string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    println!("Decoded hex: {}", str::from_utf8(&hex::decode(hex_string).unwrap()).unwrap());

    let base64_string = match hex_to_base64(hex_string) {
        Ok(v) => { v },
        Err(e) => { panic!("Error: {:?}", e); }
    };

    assert_eq!(base64_string, expected_base64_string);
}

fn challenge2() {
    // https://cryptopals.com/sets/1/challenges/2
    let str1 = "1c0111001f010100061a024b53535009181c";
    let str2 = "686974207468652062756c6c277320657965";
    let expected_str3 = "746865206b696420646f6e277420706c6179";

    let bytes1 = hex::decode(str1).unwrap();
    let bytes2 = hex::decode(str2).unwrap();
    let bytes3 = xor_bytes(bytes1.clone(), bytes2.clone());

    let str3 = hex::encode(bytes3.clone());

    println!("String 1: {}", str::from_utf8(&bytes1).unwrap());
    println!("String 2: {}", str::from_utf8(&bytes2).unwrap());
    println!("String 3: {}", str::from_utf8(&bytes3).unwrap());

    assert_eq!(expected_str3, str3);
}

fn challenge3() {
    // https://cryptopals.com/sets/1/challenges/3
    let hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let ciphertext_bytes = hex::decode(hex_str).unwrap();

    let mut scores = HashMap::new();

    // xor with each character
    for i in 0..255 {
        let key_bytes = vec![i];
        let plaintext_bytes = xor_bytes(ciphertext_bytes.clone(), key_bytes);
        //scores.insert(i, score);
        //println!("key {}, plaintext {}", i, str::from_utf8(&plaintext_bytes).unwrap());
    }

    //let string = str::from_utf8(&bytes).unwrap();
}

fn hex_to_base64(hex_string: &str) -> Result<String, String> {
    // Convert hex to Vec<u8>, an array of bytes
    let bin = match hex::decode(hex_string) {
        Ok(v) => v,
        Err(_) => { return Err(String::from("Error converting hex to bytes")); }
    };

    // Convert bin to base64
    let base64_string = base64::encode(&bin);

    Ok(base64_string)
}

fn xor_bytes(bytes1: Vec<u8>, bytes2: Vec<u8>) -> Vec<u8> {
    // The returned vector will have the length of bytes1

    // bytes3 = bytes1 xor bytes2
    let mut bytes3 = vec![];
    for i in 0..bytes1.len() {
        bytes3.push(bytes1[i] ^ bytes2[i % bytes2.len()])
    }
    bytes3
}

fn score_plaintext(plaintext: Vec<u8>) -> f32 {
    // Evaluate the bytes for likeliness of being English plaintext, and return
    // a score. The higher the score, the more likely it's plaintext.

    // For each character, I'm going to add the relative frequency that it appears
    // in English to the score. If it's a non-printable ASCII character, I subtract
    // 5, and if if it's printable but not alphabetic, it doesn't change the score.

    // Relative frequency of letters in the English language from:
    // https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language

    let mut frequency = HashMap::new();
    frequency.insert('a', 8.167);
    frequency.insert('b', 1.492);
    frequency.insert('c', 2.782);
    frequency.insert('d', 4.253);
    frequency.insert('e', 12.702);
    frequency.insert('f', 2.228);
    frequency.insert('g', 2.015);
    frequency.insert('h', 6.094);
    frequency.insert('i', 6.966);
    frequency.insert('j', 0.153);
    frequency.insert('k', 0.772);
    frequency.insert('l', 4.025);
    frequency.insert('m', 2.406);
    frequency.insert('n', 6.749);
    frequency.insert('o', 7.507);
    frequency.insert('p', 1.929);
    frequency.insert('q', 0.095);
    frequency.insert('r', 5.987);
    frequency.insert('s', 6.327);
    frequency.insert('t', 9.056);
    frequency.insert('u', 2.758);
    frequency.insert('v', 0.978);
    frequency.insert('w', 2.360);
    frequency.insert('x', 0.150);
    frequency.insert('y', 1.974);
    frequency.insert('z', 0.074);

    let mut score: f32 = 0.0;
    for c in &plaintext {
        // If it's alphanumeric, punctuation, or whitespace
        if (c as char).is_ascii_alphanumeric() || (c as char).is_ascii_punctuation() || (c as char).is_ascii_whitespace() {
            if (c as char).is_ascii_alphabetic() {
                let key = (c as char).to_ascii_lowercase();
                score += match frequency.get(&key) {
                    None => 0.0,
                    Some(v) => *v
                };
            }
        }
        // It doesn't seem to be printable, so punish
        else {
            score -= 5.0;
        }
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_base64() {
        assert_eq!(
            hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap(),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn test_xor_bytes() {
        assert_eq!(
            xor_bytes(vec![1, 2, 3], vec![130, 140, 150]),
            vec![131, 142, 149]
        );
        assert_eq!(
            xor_bytes(vec![1, 2, 3, 4, 5], vec![128]),
            vec![129, 130, 131, 132, 133]
        );
    }

    #[test]
    fn test_score_plaintext() {
        let score1 = score_plaintext("the quick brown fox jumped over the crazy dog");
        let score2 = score_plaintext("إيو. لمّ في مرجع والعتاد اقتصادية. مكن عن اتّجة");
        assert!(score1 > score2);
    }
}
