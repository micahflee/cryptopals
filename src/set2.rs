extern crate base64;

use std::str;
use colored::Colorize;
use crypto::{blockmodes, buffer, aes};
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

use set1::{get_file_contents, xor_bytes, bytes_into_blocks};

pub fn index(challenge: u32) {
    if challenge == 9 {
        challenge9();
    } else if challenge == 10 {
        challenge10();
    } else {
        // Run all challanges
        challenge9();
        challenge10();
    }
}

fn challenge9() {
    // https://cryptopals.com/sets/2/challenges/9
    println!("\n{}", "Implement PKCS#7 padding".blue().bold());

    let mut block = "YELLOW SUBMARINE".as_bytes().to_vec();
    pkcs7_padding(&mut block, 20);
    println!("{:?}", block);
}

fn challenge10() {
    // https://cryptopals.com/sets/2/challenges/10
    println!("\n{}", "Implement CBC mode".blue().bold());

    let iv = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let key = "YELLOW SUBMARINE".as_bytes().to_vec();

    let ciphertext_base64 = get_file_contents("data/set2/10.txt").unwrap().replace("\n", "");
    let ciphertext = base64::decode(&ciphertext_base64).unwrap();

    let blocks = bytes_into_blocks(ciphertext, 16);

    let mut plaintext = vec![];

    // The previous block starts out as the IV
    let mut prev_block = iv.clone();
    for block in blocks {
        // XOR the block with the previous block, and create a new previous block
        let entangled_block = xor_bytes(block, prev_block.clone());
        prev_block = entangled_block.clone();

        // Decrypt the block and append it to plaintext
        let mut plaintext_block = aes128_ecb_decrypt(entangled_block, key.clone());

        // Display the block
        match str::from_utf8(&plaintext_block) {
            Ok(v) => println!("Block decrypted: {:?}", v),
            Err(_) => println!("Block decrypted: (invalid utf8, can't display)")
        }
        plaintext.append(&mut plaintext_block);
    }

    // Did we decrypt?
    //println!("Plaintext:\n\n{}", str::from_utf8(&plaintext));
}

fn pkcs7_padding(data: &mut Vec<u8>, blocksize: usize) {
    // Add PKCS#7 padding to the end of data until it's length is a multiple of blocksize

    // How much padding do we need?
    let padding: u8 = (blocksize - (data.len() % blocksize)) as u8;

    // Append that much padding to the end
    for _ in 0..padding {
        data.push(padding);
    }
}

fn aes128_ecb_decrypt(ciphertext: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    // AES-128 ECB decrypt function, basically challenge 7
    let mut decryptor = aes::ecb_decryptor(aes::KeySize::KeySize128, &key, blockmodes::NoPadding);

    let mut plaintext = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(ciphertext.as_slice());
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(v) => v,
            Err(_) => panic!("Error decrypting AES-128-ECB")
        };
        plaintext.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    plaintext
}

#[cfg(test)]
mod tests {
    use super::*;
    use set1::get_file_contents;

    #[test]
    fn test_pkcs7_padding() {
        let mut block = "YELLOW SUBMARINE".as_bytes().to_vec();
        pkcs7_padding(&mut block, 20);
        assert_eq!(block, "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().to_vec());
    }

    #[test]
    fn test_aes128_ecb_decrypt() {
        let ciphertext_base64 = get_file_contents("data/set1/7.txt").unwrap().replace("\n", "");
        let ciphertext = base64::decode(&ciphertext_base64).unwrap();
        let expected_plaintext_string = get_file_contents("data/set1/7-plaintext.txt").unwrap();
        let expected_plaintext = expected_plaintext_string.as_bytes().to_vec();

        let key = "YELLOW SUBMARINE".as_bytes().to_vec();
        let plaintext = aes128_ecb_decrypt(ciphertext, key);

        assert_eq!(plaintext, expected_plaintext);
    }
}
