extern crate base64;
extern crate rand;

use std::str;
use rand::{Rng, EntropyRng};
use colored::Colorize;
use crypto::{blockmodes, buffer, aes};
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use queryst::parse;

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
    } else if challenge == 13 {
        challenge13();
    } else if challenge == 14 {
        challenge14();
    } else if challenge == 15 {
        challenge15();
    } else if challenge == 15 {
        challenge16();
    } else {
        // Run all challanges
        challenge9();
        challenge10();
        challenge11();
        challenge12();
        challenge13();
        challenge14();
        challenge15();
        challenge16();
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
    let mut prev_block = vec![];;
    let mut block_index = 0;
    let mut quit = false;
    loop {
        let mut unknown_block = vec![];
        let mut message = vec![];

        // Assuming blocksize is 4, unknown is "123456", padding is "x".
        // Find the first block (block_index == 0) like this:
        // [AAAA][1234][56xx]
        // [AAA?][2345][5xxx]
        // [AA1?][3456][xxxx]
        // [A12?][456x]
        // [123?][56xx]
        // Found the first block: [1234] <-- prev_block

        // If we know the first block, I want my message to be two blocks
        // long, but where the first block starts out as prev_block like this:
        // [1234][AAAA][1234][56xx]
        // [234?][AAA1][2345][6xxx]
        // [345?][AA12][3456][xxxx]
        // Found the next block: [3456]  <-- prev_block

        // Append the previous block to the message
        // (If this is the first loop, prev_block is empty)
        message.append(&mut prev_block);

        // Add blocksize worth of 'A's to the message
        for _ in 0..blocksize {
            message.push('A' as u8);
        }

        // Brute force the unknown byte
        for _ in 0..blocksize {
            // Delete a byte from the beginning of the message
            message.remove(0);

            // Figure out the ciphertext byte in its place
            let ciphertext = encryption_oracle2(key.clone(), message.clone());
            let real_ciphertext_block;

            // Still finding the first block
            if block_index == 0 {
                // 1st block, [AAA1][2345][6xxx]
                //      mine/real ^
                real_ciphertext_block = &ciphertext[0..blocksize];

                // Append the unknown text so far to the message
                message.append(&mut unknown_block.clone());
            }

            // Already know the first block, finding later blocks
            else {
                // when brute forcing 2nd block, 3rd block is real, [234A][AAA1][2345][6xxx]
                //                                                 mine ^      real ^
                real_ciphertext_block = &ciphertext[((block_index + 1) * blocksize)..((block_index + 2) * blocksize)];
            }

            // Figure out what byte makes the encrypted byte
            let mut found = false;
            for i in 0..255 {
                // Make a guess for that byte
                if block_index == 0 {
                    message.push(i);
                } else {
                    message[blocksize-1] = i;
                }

                // Encrypt it, store the encrypted block
                let ciphertext = encryption_oracle2(key.clone(), message.clone());
                let guess_ciphertext_block = &ciphertext[0..blocksize];

                if block_index == 0 {
                    // Remove that byte from the message
                    let message_len = message.len();
                    message.remove(message_len - 1);
                }

                // Did we find a new byte?
                if real_ciphertext_block == guess_ciphertext_block {
                    if block_index == 0 {
                        // Remove the unknown text bytes from the message
                        for _ in 0..unknown_block.len() {
                            let message_len = message.len();
                            message.remove(message_len - 1);
                        }
                    }

                    // Add the new byte to the list of bytes that work
                    unknown_block.push(i);
                    found = true;
                    println!("{:?} {:?}", str::from_utf8(&unknown).unwrap(), str::from_utf8(&unknown_block).unwrap());
                    break;
                }
            }

            // Did we not find it?
            if !found {
                // I think is a good time to break out of the loop
                quit = true;
            }
        }
        println!("unknown_block: {:?}", &unknown_block);
        prev_block = unknown_block.clone();
        unknown.append(&mut unknown_block);

        block_index += 1;

        if quit {
            break;
        }
    }

    println!("\nPLAINTEXT:\n{}", str::from_utf8(&unknown).unwrap());
}

fn challenge13() {
    // https://cryptopals.com/sets/2/challenges/13
    println!("\n{}", "ECB cut-and-paste".blue().bold());

    // Generate a random key
    let key = gen_key(16);

    // Let's see what profile_for stings look like
    // profile_for("test") returns "email=test&uid=10&role=user"
    // "----------------" "----------------"
    // "email=AAAAAAAAAA" "AAA&uid=10&role=" "user"                         <- profile_for("AAAAAAAAAAAAA")
    // "email=AAAAAAAAAA" "admin&uid=10&rol" "e=user"                       <- profile_for("AAAAAAAAAAadmin")
    // "email=AAAAAAAAAA" "AAAAAAAAAAAAAAA&" "uid=10&role=user" "[padding]" <- profile_for("AAAAAAAAAAAAAAAAAAAAAAAAA")

    let ciphertext1 = challenge13_encrypt(key.clone(), &profile_for("AAAAAAAAAAAAA"));
    let ciphertext2 = challenge13_encrypt(key.clone(), &profile_for("AAAAAAAAAAadmin"));
    let ciphertext3 = challenge13_encrypt(key.clone(), &profile_for("AAAAAAAAAAAAAAAAAAAAAAAAA"));
    let mut ciphertext1_blocks = bytes_into_blocks(ciphertext1, 16);
    let mut ciphertext2_blocks = bytes_into_blocks(ciphertext2, 16);
    let mut ciphertext3_blocks = bytes_into_blocks(ciphertext3, 16);
    println!("ciphertext1_blocks length: {}", ciphertext1_blocks.len());
    println!("ciphertext2_blocks length: {}", ciphertext2_blocks.len());
    println!("ciphertext3_blocks length: {}", ciphertext3_blocks.len());

    println!("String will be: email=AAAAAAAAAAAAA&uid=10&role=admin&uid=10&rol");

    let mut patchwork_ciphertext = vec![];
    patchwork_ciphertext.append(&mut ciphertext1_blocks[0]);
    patchwork_ciphertext.append(&mut ciphertext1_blocks[1]);
    patchwork_ciphertext.append(&mut ciphertext2_blocks[1]);
    patchwork_ciphertext.append(&mut ciphertext3_blocks[3]); // Padding-only block

    challenge13_decrypt_and_parse(key.clone(), patchwork_ciphertext);
}

fn challenge14() {
    // https://cryptopals.com/sets/2/challenges/12
    println!("\n{}", "Byte-at-a-time ECB decryption (Harder)".blue().bold());

    let key = gen_key(16);
    let blocksize = 16;

    // Generate a random prefix between 1 and 16 bytes long
    let mut rng = EntropyRng::new();
    let prefix = gen_key(rng.gen_range(1, 17));

    // I need to use the oracle to detect how many bytes we need to prepend to our own message
    // (called message_prefix, not to be confused with prefix), in order to cause the prefix to
    // fill up the block.

    // I can do this by detecting ECB. I fill up my message with two blocks of 'A's, and then see if
    // any blocks repeat. I add an 'A' to the message until they do. So if blocksize is 8 and prefix
    // length 5, my message is 16 'A's. Then I add 3 more 'A's before I detect ECB. That means my
    // message_prefix should be 3.

    // [XXXXXAAA][AAAAAAAA][AAAAAAAA]
    //                           ^^^ extra 3 bytes to make ECB detectable


    // Start with two blocks worth of 'A's to the message, in order to detect ECB mode
    let mut message = vec![];
    for _ in 0..(blocksize * 2) {
        message.push('A' as u8);
    }

    // Check for ECB mode, add an 'A', check again, etc. until we find ECB mode
    loop {
        let ciphertext = encryption_oracle3(key.clone(), prefix.clone(), message.clone());
        if is_ciphertext_ecb(ciphertext, blocksize) {
            break;
        }
        message.push('A' as u8);
    }
    let message_prefix_size = message.len() - (blocksize * 2);
    println!("Prepend {} bytes to the message to complete the block", message_prefix_size);

    // Create the message prefix
    let mut message_prefix = vec![];
    for _ in 0..message_prefix_size {
        message_prefix.push('B' as u8);
    }

    // Now I just need to append message_prefix before each oracle request

    // Create variable to hold the unknown string
    let mut unknown = vec![];

    // Learn the unknown string one block at a time, until we run out of blocks
    let mut prev_block = vec![];;
    let mut block_index = 0;
    let mut quit = false;
    loop {
        let mut unknown_block = vec![];
        let mut message = vec![];

        // Append the previous block to the message
        // (If this is the first loop, prev_block is empty)
        message.append(&mut prev_block);

        // Add blocksize worth of 'A's to the message
        for _ in 0..blocksize {
            message.push('A' as u8);
        }

        // Brute force the unknown byte
        for _ in 0..blocksize {
            // Delete a byte from the beginning of the message
            message.remove(0);

            // Figure out the ciphertext byte in its place
            let mut full_message = vec![];
            full_message.append(&mut message_prefix.clone());
            full_message.append(&mut message.clone());
            let mut ciphertext = encryption_oracle3(key.clone(), prefix.clone(), full_message);
            let real_ciphertext_block;

            // The first block is taken up by prefix concated with message_prefix, so skip that block
            // when getting the real_ciphertext_block

            // Still finding the first block
            if block_index == 0 {
                real_ciphertext_block = &ciphertext[blocksize..(blocksize * 2)];
                message.append(&mut unknown_block.clone());
            } else {
                real_ciphertext_block = &ciphertext[((block_index + 2) * blocksize)..((block_index + 3) * blocksize)];
            }

            // Figure out what byte makes the encrypted byte
            let mut found = false;
            for i in 0..255 {
                // Make a guess for that byte
                if block_index == 0 {
                    message.push(i);
                } else {
                    message[blocksize-1] = i;
                }

                // Encrypt it, store the encrypted block
                let mut full_message = vec![];
                full_message.append(&mut message_prefix.clone());
                full_message.append(&mut message.clone());
                let mut ciphertext = encryption_oracle3(key.clone(), prefix.clone(), full_message);

                // Same with guess_ciphertext_block, skip the first block
                let guess_ciphertext_block = &ciphertext[blocksize..(blocksize * 2)];

                if block_index == 0 {
                    // Remove that byte from the message
                    let message_len = message.len();
                    message.remove(message_len - 1);
                }

                // Did we find a new byte?
                if real_ciphertext_block == guess_ciphertext_block {
                    if block_index == 0 {
                        // Remove the unknown text bytes from the message
                        for _ in 0..unknown_block.len() {
                            let message_len = message.len();
                            message.remove(message_len - 1);
                        }
                    }

                    // Add the new byte to the list of bytes that work
                    unknown_block.push(i);
                    found = true;
                    println!("{:?} {:?}", str::from_utf8(&unknown).unwrap(), str::from_utf8(&unknown_block).unwrap());
                    break;
                }
            }

            // Did we not find it?
            if !found {
                // I think is a good time to break out of the loop
                quit = true;
            }
        }
        println!("unknown_block: {:?}", &unknown_block);
        prev_block = unknown_block.clone();
        unknown.append(&mut unknown_block);

        block_index += 1;

        if quit {
            break;
        }
    }

    println!("\nPLAINTEXT:\n{}", str::from_utf8(&unknown).unwrap());
}

fn challenge15() {
    // https://cryptopals.com/sets/2/challenges/15
    println!("\n{}", "PKCS#7 padding validation".blue().bold());

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
    println!("validate_pkcs7_padding works as advertised");
}

fn challenge16() {
    // https://cryptopals.com/sets/2/challenges/16
    println!("\n{}", "CBC bitflipping attacks".blue().bold());

    // Random key
    let key = gen_key(16);

    // TODO: finish
}

fn pkcs7_padding(data: &mut Vec<u8>, blocksize: usize) {
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

fn encryption_oracle3(key: Vec<u8>, prefix: Vec<u8>, message: Vec<u8>) -> Vec<u8> {
    // Take your oracle function from #12. Now generate a random count of random bytes and
    // prepend this string to every plaintext. You are now doing:
    //   AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
    // Same goal: decrypt the target-bytes.
    let mut new_message = vec![];

    // Add between 0 and 16 random bytes to the beginning
    new_message.append(&mut prefix.clone());
    new_message.append(&mut message.clone());

    encryption_oracle2(key, new_message)
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

fn profile_for(email: &str) -> String {
    // Now write a function that encodes a user profile in that format, given an email address.
    // You should have something like: profile_for("foo@bar.com") ... and it should produce:
    // {
    //   email: 'foo@bar.com',
    //   uid: 10,
    //   role: 'user'
    // }
    //  ... encoded as:
    // email=foo@bar.com&uid=10&role=user
    //  Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them,
    // quote them, whatever you want to do, but don't let people set their email address to
    // "foo@bar.com&role=admin".

    let sanitized_email = email.replace("&", "").replace("=", "");

    let mut s = String::from("email=");
    s.push_str(sanitized_email.as_str());
    s.push_str("&uid=10&role=user");
    s
}

fn challenge13_encrypt(key: Vec<u8>, message: &str) -> Vec<u8> {
    // Encrypt the message to the key, return the ciphertext
    let plaintext = message.as_bytes().to_vec();
    let mut encryptor = aes::ecb_encryptor(aes::KeySize::KeySize128, &key, blockmodes::PkcsPadding);
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

fn challenge13_decrypt_and_parse(key: Vec<u8>, ciphertext: Vec<u8>) {
    // Decrypt the ciphertext, parse it with queryst::parse, and print the resuling data structure
    let mut decryptor = aes::ecb_decryptor(aes::KeySize::KeySize128, &key, blockmodes::PkcsPadding);
    let mut plaintext = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(ciphertext.as_slice());
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    loop {
        let result = match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(v) => v,
            Err(_) => panic!("Error decrypting")
        };
        plaintext.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    // Convert plaintext to a string
    let plaintext_string = str::from_utf8(&plaintext).unwrap();

    // Decode it
    let object = parse(plaintext_string).unwrap();
    println!("{:?}", object);
}

fn validate_pkcs7_padding(padded_plaintext: Vec<u8>) -> Result<Vec<u8>, String> {
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

fn cbc_bitflipping_encrypt(key: Vec<u8>, iv: Vec<u8>, message: String) -> Vec<u8> {
    // Strip ";" and "=" from the message
    let stripped_message = message.replace(";", "").replace("=", "");

    // Build the plaintext string
    let mut plaintext = vec![];
    plaintext.append(&mut "comment1=cooking%20MCs;userdata=".as_bytes().to_vec());
    plaintext.append(&mut stripped_message.as_bytes().to_vec());
    plaintext.append(&mut ";comment2=%20like%20a%20pound%20of%20bacon".as_bytes().to_vec());

    // Encrypt with AES CBC mode
    let mut encryptor = aes::cbc_encryptor(aes::KeySize::KeySize128, &key, &iv, blockmodes::PkcsPadding);
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

fn cbc_bitflipping_decrypt(key: Vec<u8>, iv: Vec<u8>, ciphertext: Vec<u8>) -> bool {
    // Decrypt with AES CBC mode
    let mut decryptor = aes::cbc_decryptor(aes::KeySize::KeySize128, &key, &iv, blockmodes::PkcsPadding);
    let mut plaintext = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(ciphertext.as_slice());
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    loop {
        let result = match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(v) => v,
            Err(_) => panic!("Error encrypting")
        };
        plaintext.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    // Print the plaintext message
    match str::from_utf8(&plaintext) {
        Ok(v) => println!("{}", v),
        Err(_) => println!("{:?}", &plaintext)
    };

    // Search for ";admin=true;"
    let search = ";admin=true;".as_bytes().to_vec();
    vec_contains(plaintext, search)
}

fn vec_contains(haystack: Vec<u8>, needle: Vec<u8>) -> bool {
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

    #[test]
    fn test_profile_for() {
        assert_eq!(
            profile_for("foo@bar.com"),
            String::from("email=foo@bar.com&uid=10&role=user")
        );
        assert_eq!(
            profile_for("foo@bar.com&role=admin"),
            String::from("email=foo@bar.comroleadmin&uid=10&role=user")
        );
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
    }

    #[test]
    fn test_vec_contains() {
        let haystack = "the quick brown fox jumps over the lazy dog".as_bytes().to_vec();
        assert_eq!(vec_contains(haystack.clone(), "brown fox".as_bytes().to_vec()), true);
        assert_eq!(vec_contains(haystack.clone(), "blue fox".as_bytes().to_vec()), false);
    }
}
