extern crate hex;
extern crate base64;

use std::str;

pub fn index() {
    challenge1();
}

fn challenge1() {
    println!("Challenge 1.1");

    let hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected_base64_string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let base64_string = match hex_to_base64(hex_string) {
        Ok(v) => { v },
        Err(e) => { panic!("Error: {:?}", e); }
    };

    assert_eq!(base64_string, expected_base64_string);
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
}
