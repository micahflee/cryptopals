extern crate base64;
extern crate rand;

use std::str;
use rand::{Rng, EntropyRng};
use colored::Colorize;
use crypto::{blockmodes, buffer, aes};
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

use set1::{get_file_contents, xor_bytes, bytes_into_blocks};

pub fn index(challenge: u32) {
    if challenge == 9 {
        challenge9();
    } else if challenge == 10 {
        challenge10();
    } else if challenge == 11 {
        challenge11();
    } else {
        // Run all challanges
        challenge9();
        challenge10();
        challenge11();
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
    let mut prev_block = iv;
    for block in blocks {
        // Decrypt the block, and then xor it with the previous block
        let plaintext_block1 = aes128_ecb_decrypt(block.clone(), key.clone());
        let mut plaintext_block2 = xor_bytes(plaintext_block1, prev_block);

        // Append the block to plaintext
        plaintext.append(&mut plaintext_block2);

        // Create the new previous block
        prev_block = block;
    }

    // Did we decrypt?
    println!("Plaintext:\n\n{}", str::from_utf8(&plaintext).unwrap());
}

fn challenge11() {
    // https://cryptopals.com/sets/2/challenges/11
    println!("\n{}", "An ECB/CBC detection oracle".blue().bold());

    // Detect if the encryption is ECB or CBC. Since the blocksize is 16, I need two plaintext
    // blocks to be exactly the same in order to detect if the resulting ciphertext blocks
    // are exactly the same. Since there is 5-10 random bytes at the beginning, I need to start
    // with 11 bytes to fill the rest of the block, then 32 bytes to fill two blocks.

    // Let's try 10 times
    for _i in 0..10 {
        let ciphertext = encryption_oracle("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes().to_vec());
        let mut blocks = bytes_into_blocks(ciphertext, 16);

        // Are any of the blocks exactly the same?
        blocks.sort();
        let len1 = blocks.len();
        blocks.dedup();
        let len2 = blocks.len();
        if len1 != len2 {
            println!(".......detected ECB");
        } else {
            println!(".......detected CBC");
        }
    }
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

fn gen_key(length: usize) -> Vec<u8> {
    // Generate a vec of random bytes of length length
    let mut rng = EntropyRng::new();
    let mut key = vec![];
    for _ in 0..length {
        key.push(rng.gen::<u8>());
    }
    key
}

fn encryption_oracle(input: Vec<u8>) -> Vec<u8> {
    let mut rng = EntropyRng::new();
    let mut plaintext = vec![];

    // Add 5 to 10 bytes before and after the input
    let mut before = gen_key(rng.gen_range(5, 10));
    let mut after = gen_key(rng.gen_range(5, 10));
    plaintext.append(&mut before);
    plaintext.append(&mut input.clone());
    plaintext.append(&mut after);

    // Make a random key
    let key = gen_key(16);

    // Prepare the encryptor, either ECB or CBC
    let mut encryptor;
    let mode = rng.gen_range(0, 2);
    if mode == 0 {
        // ECB
        println!("[shh, I'm using ECB mode]");
        encryptor = aes::ecb_encryptor(aes::KeySize::KeySize128, &key, blockmodes::PkcsPadding);
    } else {
        // CBC
        println!("[shh, I'm using CBC mode]");
        let iv = gen_key(16);
        encryptor = aes::cbc_encryptor(aes::KeySize::KeySize128, &key, &iv, blockmodes::PkcsPadding);
    }

    // Encrypt
    let mut ciphertext = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(plaintext.as_slice());
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = match encryptor.encrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(v) => v,
            Err(_) => panic!("Error encrypting")
        };
        ciphertext.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    ciphertext
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

    #[test]
    fn test_gen_key() {
        let key1 = gen_key(16);
        let key2 = gen_key(16);
        assert_ne!(key1, key2);
    }
}
