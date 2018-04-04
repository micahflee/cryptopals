use std::str;

fn bytes_to_string(bytes: &[u8]) -> String {
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
