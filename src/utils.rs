use std::str;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use rand::{Rng, EntropyRng};
use crypto::{blockmodes, buffer, aes};
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use crypto::symmetriccipher::SymmetricCipherError;

pub fn xor_bytes(bytes1: Vec<u8>, bytes2: Vec<u8>) -> Vec<u8> {
    // The returned vector will have the length of bytes1

    // bytes3 = bytes1 xor bytes2
    let mut bytes3 = vec![];
    for i in 0..bytes1.len() {
        bytes3.push(bytes1[i] ^ bytes2[i % bytes2.len()])
    }
    bytes3
}

pub fn get_file_contents(filename: &str) -> Result<String, String> {
    let path = Path::new(filename);
    let display = path.display();
    let mut file = match File::open(&path) {
        Err(why) => return Err(format!("couldn't open {}: {}", display, why.description())),
        Ok(file) => file,
    };

    let mut s = String::new();
    match file.read_to_string(&mut s) {
        Err(why) => return Err(format!("couldn't read {}: {}", display, why.description())),
        Ok(_) => {},
    }
    Ok(s)
}

pub fn bytes_into_blocks(bytes: &[u8], blocksize: usize) -> Vec<Vec<u8>> {
    // Split bytes into blocks of length blocksize, and return a vec of blocks
    // Break ciphertext into keysize blocks
    let mut blocks = vec![];
    let mut i = 0;
    loop {
        if bytes.len() >= blocksize * (i + 1) {
            let block = &bytes[(blocksize * i)..(blocksize * (i + 1))];
            blocks.push(block.to_vec());
            i += 1;
        } else {
            let block = &bytes[(blocksize * i)..bytes.len()];
            if block.len() > 0 {
                blocks.push(block.to_vec());
            }
            break;
        }
    }
    blocks
}

pub fn blocks_into_bytes(blocks: Vec<Vec<u8>>) -> Vec<u8> {
    // Take a vec of blocks and convert them into a single vec of bytes
    let mut bytes = vec![];
    for block in blocks {
        bytes.append(&mut block.clone());
    }
    bytes
}

pub fn pkcs7_padding(data: &mut Vec<u8>, blocksize: usize) {
    // Add PKCS#7 padding to the end of data until it's length is a multiple of blocksize

    // How much padding do we need?
    let mut padding: u8 = (blocksize - (data.len() % blocksize)) as u8;
    if padding == 0 {
        padding += blocksize as u8;
    }

    // Append that much padding to the end
    for _ in 0..padding {
        data.push(padding);
    }
}

pub fn gen_random_bytes(rng: &mut EntropyRng, length: usize) -> Vec<u8> {
    // Generate a vec of random bytes of length length
    let mut key = vec![];
    for _ in 0..length {
        key.push(rng.gen::<u8>());
    }
    key
}

pub fn vec_contains(haystack: Vec<u8>, needle: Vec<u8>) -> bool {
    if haystack.len() < needle.len() {
        return false;
    }

    // Search for haystack for needle
    let mut i = 0;
    for byte in &haystack {
        if *byte == needle[i] {
            i += 1;
            if i == needle.len() {
                return true;
            }
        } else {
            i = 0;
        }
    }
    false
}

pub fn bytes_to_string(bytes: &[u8]) -> String {
    // Convert a byte array to a printable string, even if it contains bytes that can't be encoded
    // in utf8. Instead, display their hex values at that point (not unicode).
    let mut s = String::new();
    for c in bytes {
        let escaped_c = &(*c as char).escape_default().to_string();
        if escaped_c.starts_with("\\u") {
            s.push_str("\\x");
            s.push_str(&format!("{:02x}", c));
        } else {
            s.push_str(escaped_c);
        }
    }
    s
}

pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut encryptor = aes::cbc_encryptor(aes::KeySize::KeySize128, &key, &iv, blockmodes::PkcsPadding);
    let mut ciphertext = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(plaintext);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = match encryptor.encrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(v) => v,
            Err(_) => return Err(String::from("Error encrypting"))
        };
        ciphertext.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    Ok(ciphertext)
}

pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(aes::KeySize::KeySize128, &key, &iv, blockmodes::PkcsPadding);
    let mut plaintext = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(ciphertext);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        // TODO: I'm running into a problem where when I send junk ciphertext into this function,
        // sometimes decryptor.decrypt panics and it never should:
        // thread 'main' panicked at 'attempt to subtract with overflow', /home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/rust-crypto-0.2.36/src/buffer.rs:140:45
        let result = match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(v) => v,
            Err(v) => return Err(v)
        };
        plaintext.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    Ok(plaintext)
}

pub fn validate_pkcs7_padding(padded_plaintext: Vec<u8>) -> Result<Vec<u8>, String> {
    // Determines if padded_plaintext has valid PKCS#7 padding, and strips the padding off

    // Error if plaintext is empty
    if padded_plaintext.is_empty() {
        return Err(String::from("plaintext is empty"));
    }

    // What is the last byte?
    let length = padded_plaintext.len();
    let last_byte = padded_plaintext[length - 1];

    // The value of the last byte cannot be bigger than the length of the plaintext
    if last_byte as usize > padded_plaintext.len() {
        return Err(String::from("invalid padding, last byte is larger than the length of the plaintext"));
    }

    // And it cannot be 0
    if last_byte == 0 {
        return Err(String::from("invalid padding, last byte is 0"))
    }

    // Make sure that the last last_byte bytes all equal last_byte
    let mut success = true;
    for i in 0..last_byte {
        if padded_plaintext[length - 1 - i as usize] != last_byte {
            success = false;
        }
    }
    if !success {
        return Err(String::from("invalid padding"));
    }

    // Strip the padding
    let plaintext = padded_plaintext[0..(length - last_byte as usize)].to_vec();
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_bytes_into_blocks() {
        let bytes = "AAAABBBBCCCCDD".as_bytes().to_vec();
        let blocks = bytes_into_blocks(&bytes, 4);
        assert_eq!(
            blocks,
            vec![
                "AAAA".as_bytes().to_vec(),
                "BBBB".as_bytes().to_vec(),
                "CCCC".as_bytes().to_vec(),
                "DD".as_bytes().to_vec()
            ]
        );
    }

    #[test]
    fn test_pkcs7_padding() {
        let mut block = "YELLOW SUBMARINE".as_bytes().to_vec();
        pkcs7_padding(&mut block, 20);
        assert_eq!(block, "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().to_vec());
    }

    #[test]
    fn test_gen_random_bytes() {
        let mut rng = EntropyRng::new();
        let key1 = gen_random_bytes(&mut rng, 16);
        let key2 = gen_random_bytes(&mut rng, 16);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_vec_contains() {
        let haystack = "the quick brown fox jumps over the lazy dog".as_bytes().to_vec();
        assert_eq!(vec_contains(haystack.clone(), "brown fox".as_bytes().to_vec()), true);
        assert_eq!(vec_contains(haystack.clone(), "blue fox".as_bytes().to_vec()), false);
    }

    #[test]
    fn test_bytes_to_string() {
        assert_eq!(
            bytes_to_string(&[104, 101, 108, 108, 111]),
            String::from("hello")
        );
        assert_eq!(
            bytes_to_string(&[104, 101, 108, 108, 111, 0, 1, 2, 3, 4, 5, 255]),
            String::from("hello\\x00\\x01\\x02\\x03\\x04\\x05\\xff")
        );
    }

    #[test]
    fn test_aes_cbc() {
        let plaintext = "It uses hand-drawn stick figure graphics and writing characterized by surreal humor, word play, parody and references to popular culture. In KoL, a player's character fights monsters for experience, and acquiring meat (the game's currency), and/or items, through a turn-based system. Players may also interact with each other through player versus player competition, participate in the in-game economy by trading goods and services, organize their characters into clans, work together to complete clan dungeons, and speak to each other in many different chat channels.".as_bytes().to_vec();
        let mut rng = EntropyRng::new();
        let key = gen_random_bytes(&mut rng, 16);
        let iv = gen_random_bytes(&mut rng, 16);

        let ciphertext = aes_cbc_encrypt(&key, &iv, &plaintext).unwrap();
        let plaintext2 = aes_cbc_decrypt(&key, &iv, &ciphertext).unwrap();

        assert_eq!(plaintext, plaintext2);
    }

    #[test]
    fn test_validate_pkcs7_padding() {
        assert_eq!(
            validate_pkcs7_padding("ICE ICE BABY\x04\x04\x04\x04".as_bytes().to_vec()),
            Ok("ICE ICE BABY".as_bytes().to_vec())
        );
        assert_eq!(
            validate_pkcs7_padding("ICE ICE BABY\x05\x05\x05\x05".as_bytes().to_vec()),
            Err(String::from("invalid padding"))
        );
        assert_eq!(
            validate_pkcs7_padding("ICE ICE BABY\x01\x02\x03\x04".as_bytes().to_vec()),
            Err(String::from("invalid padding"))
        );
        assert_eq!(
            validate_pkcs7_padding("AAAAAAAAAAAAAAA\x00".as_bytes().to_vec()),
            Err(String::from("invalid padding, last byte is 0"))
        );
    }

    #[test]
    fn test_blocks_into_bytes() {
        let blocks = vec![
            "AAAA".as_bytes().to_vec(),
            "BBBB".as_bytes().to_vec(),
            "CCCC".as_bytes().to_vec(),
            "DD".as_bytes().to_vec()
        ];
        let bytes = blocks_into_bytes(blocks);
        assert_eq!(
            bytes,
            "AAAABBBBCCCCDD".as_bytes().to_vec()
        );
    }
}
