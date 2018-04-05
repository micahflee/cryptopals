extern crate base64;

use colored::Colorize;
use rand::{Rng, EntropyRng};

use utils::{gen_key, aes_cbc_encrypt, aes_cbc_decrypt, bytes_to_string, pkcs7_padding,
            validate_pkcs7_padding};

pub fn index(challenge: u32) {
    if challenge == 17 {
        challenge17();
    } else if challenge == 18 {
        challenge18();
    } else if challenge == 19 {
        challenge19();
    } else if challenge == 20 {
        challenge20();
    } else if challenge == 21 {
        challenge21();
    } else if challenge == 22 {
        challenge22();
    } else if challenge == 23 {
        challenge23();
    } else if challenge == 24 {
        challenge24();
    } else {
        // Run all challanges
        challenge17();
        challenge18();
        challenge19();
        challenge20();
        challenge21();
        challenge22();
        challenge23();
        challenge24();
    }
}

fn challenge17() {
    // https://cryptopals.com/sets/3/challenges/17
    println!("\n{}", "Challenge 17: The CBC padding oracle".blue().bold());

    let key = gen_key(16);
    let iv = gen_key(16);

    // Give me some ciphertext
    let ciphertext = ch17_func1(key.clone(), iv.clone());
    let block_size = 16;
    let block_count = ciphertext.len() / 16;

    // Modify the ciphertext
    let mut mal_ciphertext = ciphertext.clone();

    // Decrypt the last block first, but modifying the second to last block
    //let mut plaintext_block = vec![];
    let index = block_size * (block_count - 2) - 1;
    println!("Modifying index {}, trying to decrypt index {}", index, index + block_size);
    for guess in 1..255 {
        mal_ciphertext[index] = guess;

        match ch17_func2(key.clone(), iv.clone(), mal_ciphertext.clone()) {
            Ok(padding_success) => {
                if padding_success {
                    if ciphertext[index] ^ guess != 0 {
                        let plaintext_byte = ciphertext[index + block_size] ^ guess;
                        println!("Found a byte: {} ({})", plaintext_byte as char, plaintext_byte);
                    }
                }
            },
            Err(_) => { }
        };
    }
}

fn ch17_func1(key: Vec<u8>, iv: Vec<u8>) -> Vec<u8> {
    // Take a random string, base64 decode it, add padding, encrypt it to key (using iv), and return
    // the ciphertext

    let base64_messages = vec![
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    ];

    // Choose a random string, base64 decode it, and add padding
    let mut rng = EntropyRng::new();
    let mut message = base64::decode(&base64_messages[rng.gen_range(0, base64_messages.len())]).unwrap();
    pkcs7_padding(&mut message, 16);
    println!("Message: {}", bytes_to_string(&message));

    // Encrypt
    aes_cbc_encrypt(key, iv, message).unwrap()
}

fn ch17_func2(key: Vec<u8>, iv: Vec<u8>, ciphertext: Vec<u8>) -> Result<bool, String> {
    // Decrypt ciphertext, return where or not the plaintext is properly padded

    // Decrypt
    let plaintext = match aes_cbc_decrypt(key, iv, ciphertext) {
        Ok(v) => v,
        Err(v) => return Err(v)
    };

    // Check padding
    Ok(match validate_pkcs7_padding(plaintext) {
        Ok(_) => true,
        Err(_) => false
    })
}

fn challenge18() {
    // https://cryptopals.com/sets/3/challenges/18
    println!("\n{}", "Challenge 18: Implement CTR, the stream cipher mode".blue().bold());
    println!("(not implemented yet)");
}

fn challenge19() {
    // https://cryptopals.com/sets/3/challenges/19
    println!("\n{}", "Challenge 19: Break fixed-nonce CTR mode using substitutions".blue().bold());
    println!("(not implemented yet)");
}

fn challenge20() {
    // https://cryptopals.com/sets/3/challenges/20
    println!("\n{}", "Challenge 20: Break fixed-nonce CTR statistically".blue().bold());
    println!("(not implemented yet)");
}

fn challenge21() {
    // https://cryptopals.com/sets/3/challenges/21
    println!("\n{}", "Challenge 21: Implement the MT19937 Mersenne Twister RNG".blue().bold());
    println!("(not implemented yet)");
}

fn challenge22() {
    // https://cryptopals.com/sets/3/challenges/22
    println!("\n{}", "Challenge 22: Crack an MT19937 seed".blue().bold());
    println!("(not implemented yet)");
}

fn challenge23() {
    // https://cryptopals.com/sets/3/challenges/23
    println!("\n{}", "Challenge 23: Clone an MT19937 RNG from its output".blue().bold());
    println!("(not implemented yet)");
}

fn challenge24() {
    // https://cryptopals.com/sets/3/challenges/24
    println!("\n{}", "Challenge 24: Create the MT19937 stream cipher and break it".blue().bold());
    println!("(not implemented yet)");
}
