use std::str;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

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

pub fn bytes_into_blocks(bytes: Vec<u8>, blocksize: usize) -> Vec<Vec<u8>> {
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
        let blocks = bytes_into_blocks(bytes, 4);
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
}
