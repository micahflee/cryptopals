extern crate hex;
extern crate base64;
extern crate colored;

use std::str;
use colored::Colorize;

pub fn index() {
    println!("{}", "Challenge 1.1: Convert hex to base64".blue().bold());
    challenge1();

    println!("\n{}", "Challenge 1.2: Fixed XOR".blue().bold());
    challenge2();
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
    let bytes3 = xor_bytes(bytes1.clone(), bytes2.clone()).unwrap();

    let str3 = hex::encode(bytes3.clone());

    println!("String 1: {}", str::from_utf8(&bytes1).unwrap());
    println!("String 2: {}", str::from_utf8(&bytes2).unwrap());
    println!("String 3: {}", str::from_utf8(&bytes3).unwrap());

    assert_eq!(expected_str3, str3);
}

fn hex_to_base64(hex_string: &str) -> Result<String, String> {
    // Convert hex to Vec<u8>, an array of bytes
    let bin = match hex::decode(hex_string) {
        Ok(v) => v,
        Err(_) => { return Err(String::from("Error converting hex to bytes")); }
    };

    // Uncomment to print the hex
    //println!("Decoded hex: {}", str::from_utf8(&bin).unwrap());

    // Convert bin to base64
    let base64_string = base64::encode(&bin);

    Ok(base64_string)
}

fn xor_bytes(bytes1: Vec<u8>, bytes2: Vec<u8>) -> Result<Vec<u8>, String> {
    // bytes1 and bytes2 must be the same length
    if bytes1.len() != bytes2.len() {
        return Err(String::from("bytes1 and bytes2 must have the same length"))
    }

    // bytes3 = bytes1 xor bytes2
    let mut bytes3 = vec![];
    for i in 0..bytes1.len() {
        bytes3.push(bytes1[i] ^ bytes2[i])
    }
    Ok(bytes3)
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
            Ok(vec![131, 142, 149])
        );
    }
}
