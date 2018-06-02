extern crate sha1;

use std::io::{BufReader, Error};
use std::fs::File;

/// Read file into buffer.
pub fn read_file(path: &str) -> Result<BufReader<File>, Error> {

    let file_path = File::open(path).unwrap();
    let file = BufReader::new(file_path);

    Ok(file)
}

/// Return SHA1 digest of string.
pub fn hash_password(password: &str) -> String {

    let mut shadig = sha1::Sha1::new();
    shadig.update(password.as_bytes());
    // Make uppercase for easier comparison with
    // HIBP API response
    shadig.digest().to_string().to_uppercase()

}

#[test]
fn test_sha1() {
    let hash = hash_password("qwerty");
    assert_eq!(hash, "b1b3773a05c0ed0176787a4f1574ff0075f7521e".to_uppercase());
}