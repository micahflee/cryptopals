extern crate base64;

use colored::Colorize;

use utils::{gen_random_bytes, aes_cbc_encrypt, aes_cbc_decrypt, bytes_to_string,  bytes_into_blocks};
use rand::EntropyRng;

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

    let mut rng = EntropyRng::new();
    let key = gen_random_bytes(&mut rng, 16);
    let iv = gen_random_bytes(&mut rng, 16);

    // Give me some ciphertext
    let ciphertext = ch17_func1(key.clone(), iv.clone());
    let block_size = 16;
    let blocks = bytes_into_blocks(&ciphertext, block_size);

    // The final plaintext, that we'll fill up a block at a time
    //let mut final_plaintext: Vec<u8> = vec![];

    // Loop through all of the blocks
    for block_i in 1..(blocks.len() + 1) {
        println!("ciphertext has {} blocks, working on block index {}", blocks.len(), blocks.len() - block_i);

        // Start building the malicious ciphertext, which is block 0 to block_i
        let mut malicious_ciphertext = vec![];
        for i in 0..(block_i + 1) {
            let mut block = blocks[i].clone();
            malicious_ciphertext.append(&mut block);
        }

        // The final plaintext block we're building in this loop
        //let mut plaintext_block: Vec<u8> = vec![];

        // Break the encryption one byte at a time
        for char_i in 1..(block_size + 1) {
            // Guess bytes starting at the end
            for guess in 0..255 {
                // Set the byte that we're guessing, and build a new malicious ciphertext
                // If there are 3 blocks: [AAAAAAAA] [AAAAAAAA] [AAAAAAAA]
                //                          modify this byte ^ (minus char_i)
                let index = (block_size - char_i) + (block_size * (block_i - 1));
                malicious_ciphertext[index] = guess;
                println!("guess={}, ciphertext={:?}", guess, malicious_ciphertext.clone());

                // Valid padding?
                if ch17_func2(key.clone(), iv.clone(), malicious_ciphertext.clone()) {
                    // Plaintext byte is guess ^ (padding byte)
                    let plaintext_byte = guess ^ char_i as u8;
                    println!("guess={}, plaintext byte must be {} ({}).", guess, plaintext_byte, bytes_to_string(&[plaintext_byte]));
                }
            }
            break;
        }
        break;
    }
}

fn ch17_func1(key: Vec<u8>, iv: Vec<u8>) -> Vec<u8> {
    // Take a random string, base64 decode it, add padding, encrypt it to key (using iv), and return
    // the ciphertext

    /*let base64_messages = vec![
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
    let message = base64::decode(&base64_messages[rng.gen_range(0, base64_messages.len())]).unwrap();*/
    let message = "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB".to_string().as_bytes().to_vec();

    // Print the message, in block
    println!("Message:");
    for block in bytes_into_blocks(&message, 16) {
        println!("=> \"{}\"", bytes_to_string(&block));
    }

    // Encrypt
    aes_cbc_encrypt(key, iv, message).unwrap()
}

fn ch17_func2(key: Vec<u8>, iv: Vec<u8>, ciphertext: Vec<u8>) -> bool {
    // Decrypt ciphertext, return where or not the plaintext is properly padded
    println!("debug1");

    // Decrypt
    match aes_cbc_decrypt(key, iv, ciphertext) {
        Ok(v) => {
            // For some reason the decrypt function is saying it's valid padding to end a block
            // with 0, but not have a following block of padding. I think this is invalid, so
            // check for this explicitly.
            println!("debug2");
            if v.len() % 16 == 0 {
                println!("debug3");
                if v[v.len() - 1] == 0 {
                    println!("debug4");
                    false
                } else {
                    true
                }
            } else {
                println!("Plaintext: {:?}", v.clone());
                true
            }
        },
        Err(_) => {
            println!("debug5");
            false
        }
    }
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
