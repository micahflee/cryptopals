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
    } else if challenge == 12 {
        challenge12();
    } else {
        // Run all challanges
        challenge9();
        challenge10();
        challenge11();
        challenge12();
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

fn challenge12() {
    // https://cryptopals.com/sets/2/challenges/12
    println!("\n{}", "Byte-at-a-time ECB decryption (Simple)".blue().bold());

    // Here's the secret key that I don't know
    let key = gen_key(16);

    // Discover the block size
    let mut message = vec!['A' as u8];
    let mut last_ciphertext_len = 0;
    let blocksize;
    loop {
        let ciphertext = encryption_oracle2(key.clone(), message.clone());

        // If this is the first loop iteration, just record the ciphertext length
        if last_ciphertext_len == 0 {
            last_ciphertext_len = ciphertext.len();
        }
        // In future iterations, compare the length to the previous length
        else {
            if ciphertext.len() > last_ciphertext_len {
                blocksize = ciphertext.len() - last_ciphertext_len;
                break;
            } else {
                last_ciphertext_len = ciphertext.len();
            }
        }

        // Add another 'A' to the message
        message.push('A' as u8);
    }
    println!("Block size is: {}", blocksize);

    // Now detect ECB
    message = vec![];
    for _ in 0..(blocksize*2) {
        message.push('A' as u8);
    }
    let ciphertext = encryption_oracle2(key.clone(), message.clone());
    if is_ciphertext_ecb(ciphertext, blocksize) {
        println!("Detected ECB");
    } else {
        println!("Did not detect ECB");
    }

    // Create variable to hold the unknown string
    let mut unknown = vec![];

    // Learn the unknown string one block at a time, until we run out of blocks
    let mut block_index = 0;
    loop {
        let mut unknown_block = vec![];

        // Create a message that is length blocksize
        let mut message = vec![];
        for _ in 0..blocksize {
            message.push('A' as u8);
        }

        // Brute force the block of the unknown string
        for _ in 0..blocksize {
            // Delete a byte from the message
            message.remove(0);

            // Figure out the ciphertext byte in its place
            let ciphertext = encryption_oracle2(key.clone(), message.clone());
            let encrypted_byte = ciphertext[(block_index * blocksize) + blocksize - 1];
            println!("[testing] Message={:?}, encrypted byte={}", &message, encrypted_byte);

            // Append the unknown text so far to the message
            message.append(&mut unknown_block.clone());

            // Figure out what byte makes the encrypted byte
            let mut found = vec![];
            for i in 0..255 {
                // Add byte to the message
                message.push(i);

                // Encrypt, see what the encrypted byte is
                let ciphertext = encryption_oracle2(key.clone(), message.clone());

                // Did we find a new byte?
                if ciphertext[(block_index * blocksize) + blocksize - 1] == encrypted_byte {
                    println!("Message={:?}, plaintext byte {} encrypts to {}", &message, i, ciphertext[(block_index * blocksize) + blocksize - 1]);

                    // Remove the unknown text bytes from the message
                    for _ in 0..unknown_block.len() {
                        let message_len = message.len();
                        message.remove(message_len - 1);
                    }

                    // Remove that byte from the message
                    let message_len = message.len();
                    message.remove(message_len - 1);

                    // Add the new byte to the list of bytes that work
                    found.push(i);
                } else {
                    // Remove that byte from the message
                    let message_len = message.len();
                    message.remove(message_len - 1);
                }
            }
            if found.len() == 0 {
                println!("Did not find the correct byte, quitting early :(");
                match str::from_utf8(&unknown_block) {
                    Ok(v) => println!("unknown_block: {:?}", v),
                    Err(v) => println!("unknown_block: {:?}", unknown_block)
                };
                break;
            } else if found.len() == 1 {
                // Add the only possible new byte to the unknown_block
                unknown_block.push(found[0]);
            } else {
                println!("Potential bytes: {:?}", found);
                break;
            }
        }
        //println!("unknown_block: {:?}", unknown_block);
        unknown.append(&mut unknown_block);

        block_index += 1;
        break;
    }

    //println!("unknown: {:?}", str::from_utf8(&unknown).unwrap());
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

fn encryption_oracle2(key: Vec<u8>, message: Vec<u8>) -> Vec<u8> {
    // Challenge 12 says: "Copy your oracle function to a new function that
    // encrypts buffers under ECB mode using a consistent but unknown key
    // (for instance, assign a single random key, once, to a global variable)."
    // So I'm going to just generate a random key and pass it in as an arg

    let mut plaintext = vec![];

    // Some secret string to append after the plaintext
    let after_base64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let mut after = base64::decode(&after_base64).unwrap();
    plaintext.append(&mut message.clone());
    plaintext.append(&mut after);

    // Prepare the ECB encryptor
    let mut encryptor = aes::ecb_encryptor(aes::KeySize::KeySize128, &key, blockmodes::PkcsPadding);

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

fn is_ciphertext_ecb(ciphertext: Vec<u8>, blocksize: usize) -> bool {
    // Detect if a block of ciphertext is ECB or not. Note that you must
    // have encrypted at least two identical blocks for this to work.
    let mut blocks = bytes_into_blocks(ciphertext, blocksize);
    blocks.sort();
    let len1 = blocks.len();
    blocks.dedup();
    let len2 = blocks.len();
    return len1 != len2;
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

    #[test]
    fn test_is_ciphertext_ecb() {
        let plaintext = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes().to_vec();

        // Encrypt with ECB
        let key = gen_key(16);
        let mut encryptor = aes::ecb_encryptor(aes::KeySize::KeySize128, &key, blockmodes::PkcsPadding);
        let mut ecb_ciphertext = Vec::<u8>::new();
        let mut read_buffer = buffer::RefReadBuffer::new(plaintext.as_slice());
        let mut buffer = [0; 4096];
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
        loop {
            let result = match encryptor.encrypt(&mut read_buffer, &mut write_buffer, true) {
                Ok(v) => v,
                Err(_) => panic!("Error encrypting")
            };
            ecb_ciphertext.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => { }
            }
        }

        // Encrypt with CBC
        let key = gen_key(16);
        let iv = gen_key(16);
        let mut encryptor = aes::cbc_encryptor(aes::KeySize::KeySize128, &key, &iv, blockmodes::PkcsPadding);
        let mut cbc_ciphertext = Vec::<u8>::new();
        let mut read_buffer = buffer::RefReadBuffer::new(plaintext.as_slice());
        let mut buffer = [0; 4096];
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
        loop {
            let result = match encryptor.encrypt(&mut read_buffer, &mut write_buffer, true) {
                Ok(v) => v,
                Err(_) => panic!("Error encrypting")
            };
            cbc_ciphertext.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => { }
            }
        }

        assert_eq!(is_ciphertext_ecb(ecb_ciphertext, 16), true);
        assert_eq!(is_ciphertext_ecb(cbc_ciphertext, 16), false);
    }
}
