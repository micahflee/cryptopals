use colored::Colorize;

pub fn index(challenge: u32) {
    if challenge == 9 {
        challenge9();
    } else {
        // Run all challanges
        challenge9();
    }
}

fn challenge9() {
    // https://cryptopals.com/sets/2/challenges/9
    println!("\n{}", "Implement PKCS#7 padding".blue().bold());

    let mut block = "YELLOW SUBMARINE".as_bytes().to_vec();
    pkcs7_padding(&mut block, 20);
    println!("{:?}", block);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7_padding() {
        let mut block = "YELLOW SUBMARINE".as_bytes().to_vec();
        pkcs7_padding(&mut block, 20);
        assert_eq!(block, "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().to_vec());
    }
}
