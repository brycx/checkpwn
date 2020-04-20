// MIT License

// Copyright (c) 2018-2020 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

extern crate colored;
extern crate hex;
extern crate reqwest;
extern crate sha1;
extern crate zeroize;
#[macro_use]
pub mod errors;

use self::colored::Colorize;
use self::sha1::{Digest, Sha1};
use reqwest::{header, StatusCode};
use zeroize::Zeroize;

use std::fs::File;
use std::io::{BufReader, Error};
use std::panic;

pub const CHECKPWN_USER_AGENT: &str = "checkpwn - cargo utility tool for hibp";

pub enum CheckableChoices {
    ACC,
    PASS,
    PASTE,
}

impl CheckableChoices {
    fn get_api_route(&self, search_term: &str) -> String {
        match self {
            CheckableChoices::ACC => format!(
                "https://haveibeenpwned.com/api/v3/breachedaccount/{}",
                search_term
            ),
            CheckableChoices::PASS => {
                format!("https://api.pwnedpasswords.com/range/{}", search_term)
            }
            CheckableChoices::PASTE => format!(
                "https://haveibeenpwned.com/api/v3/pasteaccount/{}",
                search_term
            ),
        }
    }
}

pub struct PassArg {
    pub password: String,
}

impl Drop for PassArg {
    fn drop(&mut self) {
        self.password.zeroize()
    }
}

/// Take the user-supplied command-line arguments and make a URL for the HIBP API.
/// If the `pass` argument has been selected, `input_data` needs to be the hashed password.
pub fn arg_to_api_route(arg: &CheckableChoices, input_data: &str) -> String {
    match arg {
        CheckableChoices::PASS => arg.get_api_route(
            // Only send the first 5 chars to the password range API
            &input_data[..5],
        ),
        _ => arg.get_api_route(input_data),
    }
}

/// Find matching key in received set of keys.
pub fn search_in_range(password_range_response: &str, hashed_key: &str) -> bool {
    for line in password_range_response.lines() {
        let pair: Vec<_> = line.split(':').collect();
        // Padded entries always have an occurrence of 0 and should be
        // discarded.
        if *pair.get(1).unwrap() == "0" {
            continue;
        }

        // Each response is truncated to only be the hash, no whitespace, etc.
        // All hashes here have a length of 35, so the useless gets dropped by
        // slicing. Don't include first five characters of own password, as
        // this also is how the HIBP API returns passwords.
        if *pair.get(0).unwrap() == &hashed_key[5..] {
            return true;
        }
    }

    false
}

/// Make a breach report based on StatusCode and print result to terminal.
pub fn breach_report(status_code: StatusCode, searchterm: &str, is_password: bool) -> ((), bool) {
    // Do not display password in terminal
    let request_key = if is_password { "********" } else { searchterm };

    match status_code {
        StatusCode::NOT_FOUND => (
            println!(
                "Breach status for {}: {}",
                request_key.cyan(),
                "NO BREACH FOUND".green()
            ),
            false,
        ),
        StatusCode::OK => (
            println!(
                "Breach status for {}: {}",
                request_key.cyan(),
                "BREACH FOUND".red()
            ),
            true,
        ),
        _ => {
            set_checkpwn_panic!(errors::STATUSCODE_ERROR);
            panic!();
        }
    }
}

/// Return a breach report based on two StatusCodes, both need to be false to be a non-breach.
fn evaluate_acc_breach(
    acc_stat: StatusCode,
    paste_stat: StatusCode,
    search_key: &str,
) -> ((), bool) {
    match (acc_stat, paste_stat) {
        (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED) => {
            set_checkpwn_panic!(errors::INVALID_API_KEY);
            panic!();
        }
        (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND) => {
            breach_report(StatusCode::NOT_FOUND, &search_key, false)
        }
        // BadRequest allowed here because the account API lets you search for usernames
        // and the paste API will return BadRequest on those
        (StatusCode::NOT_FOUND, StatusCode::BAD_REQUEST) => {
            breach_report(StatusCode::NOT_FOUND, &search_key, false)
        }
        (StatusCode::BAD_REQUEST, StatusCode::BAD_REQUEST) => {
            set_checkpwn_panic!(errors::BAD_RESPONSE_ERROR);
            panic!();
        }
        // Since the account API both takes username and emails and situation where BadRequest
        // and NotFound are returned should never occur.
        (StatusCode::BAD_REQUEST, StatusCode::NOT_FOUND) => {
            set_checkpwn_panic!(errors::BAD_RESPONSE_ERROR);
            panic!();
        }
        (StatusCode::BAD_REQUEST, StatusCode::OK) => {
            set_checkpwn_panic!(errors::BAD_RESPONSE_ERROR);
            panic!();
        }
        _ => breach_report(StatusCode::OK, &search_key, false),
    }
}

/// HIBP breach request used for `acc` arguments.
pub fn acc_breach_request(searchterm: &str, api_key: &str) {
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::USER_AGENT,
        header::HeaderValue::from_static(CHECKPWN_USER_AGENT),
    );
    headers.insert(
        "hibp-api-key",
        header::HeaderValue::from_str(api_key).unwrap(),
    );

    let client = reqwest::blocking::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap();

    set_checkpwn_panic!(errors::NETWORK_ERROR);

    let acc_stat = client
        .get(&arg_to_api_route(&CheckableChoices::ACC, searchterm))
        .send()
        .unwrap();
    let paste_stat = client
        .get(&arg_to_api_route(&CheckableChoices::PASTE, searchterm))
        .send()
        .unwrap();

    evaluate_acc_breach(acc_stat.status(), paste_stat.status(), searchterm);
}

/// Read file into buffer.
pub fn read_file(path: &str) -> Result<BufReader<File>, Error> {
    set_checkpwn_panic!(errors::READ_FILE_ERROR);
    let file_path = File::open(path).unwrap();

    Ok(BufReader::new(file_path))
}

/// Return SHA1 digest of string.
pub fn hash_password(password: &str) -> String {
    let mut sha_digest = Sha1::default();
    sha_digest.input(password.as_bytes());
    // Make uppercase for easier comparison with
    // HIBP API response
    hex::encode(sha_digest.result()).to_uppercase()
}

/// Strip all whitespace and all newlines from a given string.
pub fn strip(string: &str) -> String {
    string
        .replace("\n", "")
        .replace(" ", "")
        .replace("\'", "'")
        .replace("\t", "")
}

#[test]
fn test_strip_white_new() {
    let string_1 = String::from("fkljjsdjlksfdklj dfiwj wefwefwfe");
    let string_2 = String::from("derbrererer\n");
    let string_3 = String::from("dee\nwfweww   rb  tte rererer\n");

    assert_eq!(&strip(&string_1), "fkljjsdjlksfdkljdfiwjwefwefwfe");
    assert_eq!(&strip(&string_2), "derbrererer");
    assert_eq!(&strip(&string_3), "deewfwewwrbtterererer");
}

#[test]
fn test_sha1() {
    let hash = hash_password("qwerty");
    assert_eq!(
        hash,
        "b1b3773a05c0ed0176787a4f1574ff0075f7521e".to_uppercase()
    );
}

#[test]
fn test_make_req_and_arg_to_route() {
    // API paths taken from https://haveibeenpwned.com/API/v3
    let path = CheckableChoices::ACC.get_api_route("test@example.com");
    assert_eq!(
        path,
        "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com"
    );
    assert_eq!(
        "https://api.pwnedpasswords.com/range/B1B37",
        arg_to_api_route(&CheckableChoices::PASS, &hash_password("qwerty"))
    );
    assert_eq!(
        "https://haveibeenpwned.com/api/v3/pasteaccount/test@example.com",
        arg_to_api_route(&CheckableChoices::PASTE, "test@example.com")
    );
}

#[test]
fn test_good_argument() {
    let option_arg = CheckableChoices::ACC;
    let data_search = String::from("test@example.com");

    arg_to_api_route(&option_arg, &data_search);
}

#[should_panic]
#[test]
fn test_breach_invalid_status() {
    breach_report(StatusCode::FORBIDDEN, "saome", true);
}

#[test]
fn test_search_success_and_failure() {
    // https://api.pwnedpasswords.com/range/B1B37

    let contains_pass = String::from(
        "73678F196DE938F721CD408ED190330F5DB:3
7377BA15B8D5E12FCCBA32B074D45503D67:2
7387376AFD1B3DAB553D439C8A7D7CDDED1:2
73A05C0ED0176787A4F1574FF0075F7521E:3752262
748186F058DA83745B80E70B66D36B216A4:4
75FEC591927A596B6114ED5DAC4E4C22E04:10
76004E5282C5384DE32AFC2148BAD032450:2
769A96DED7A904FBE8F130508B2BFDDAEB1:3
76B8A2A14A15A8C22A49EC451DE9778581A:2
76C507D6248060841D4B4A4D444947E28A8:11
782C978C9120CF75BE0D93BE1330C2705E5:2
783F271CECC5F9BBC1E56B0585568C80248:5
7855E6B64AF9544B2B915CB09ADF44B507E:1",
    );

    let no_pass = String::from(
        "7EC6529B5FFD62972B78F961DA68CCC1B0E:1
7ECD0E2C0152DB98585B54B0161E05D5823:2
7ED83795FEA81B716B31648AE233AB392B6:1
7F14F4258243863575CBF33215358357C61:4
7FF32ECF384A7DBD7F1325F2AA9421747D8:6
7FFDB37B4ACDBAD365DE51962CAFFEE7412:1
801EEE3EB6CE29DB12AB39D4E4C1E579372:3
80BADE9877A506510B46A393706CE0E554F:9
818D08C77BAAD2270478CE11D97F2E64CEA:1",
    );

    let hashed_password = hash_password("qwerty");

    assert_eq!(search_in_range(&contains_pass, &hashed_password), true);
    assert_eq!(search_in_range(&no_pass, &hashed_password), false);
}

#[test]
fn test_evaluate_breach_good() {
    let (_, ok_ok) = evaluate_acc_breach(StatusCode::OK, StatusCode::OK, "search_key");
    let (_, ok_notfound) = evaluate_acc_breach(StatusCode::OK, StatusCode::NOT_FOUND, "search_key");
    let (_, notfound_ok) = evaluate_acc_breach(StatusCode::NOT_FOUND, StatusCode::OK, "search_key");
    let (_, ok_badrequest) =
        evaluate_acc_breach(StatusCode::OK, StatusCode::BAD_REQUEST, "search_key");
    let (_, notfound_badrequest) =
        evaluate_acc_breach(StatusCode::NOT_FOUND, StatusCode::BAD_REQUEST, "search_key");
    let (_, notfound_notfound) =
        evaluate_acc_breach(StatusCode::NOT_FOUND, StatusCode::NOT_FOUND, "search_key");

    assert_eq!(ok_ok, true);
    assert_eq!(ok_notfound, true);
    assert_eq!(notfound_ok, true);
    assert_eq!(ok_badrequest, true);
    assert_eq!(notfound_badrequest, false);
    assert_eq!(notfound_notfound, false);
}

#[test]
#[should_panic]
fn test_evaluate_breach_panic() {
    let _badrequest_badrequest = evaluate_acc_breach(
        StatusCode::BAD_REQUEST,
        StatusCode::BAD_REQUEST,
        "search_key",
    );
}

#[test]
#[should_panic]
fn test_evaluate_breach_panic_2() {
    let _badrequest_notfound =
        evaluate_acc_breach(StatusCode::BAD_REQUEST, StatusCode::NOT_FOUND, "search_key");
}

#[test]
#[should_panic]
fn test_evaluate_breach_panic_3() {
    let _badrequest_ok = evaluate_acc_breach(StatusCode::BAD_REQUEST, StatusCode::OK, "search_key");
}
