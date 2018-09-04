// MIT License

// Copyright (c) 2018 brycx

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

extern crate clear_on_drop;
extern crate colored;
extern crate hex;
extern crate percent_encoding;
extern crate reqwest;
extern crate sha1;
#[macro_use]
pub mod errors;

use self::colored::Colorize;
use self::percent_encoding::{utf8_percent_encode, DEFAULT_ENCODE_SET};
use self::sha1::{Digest, Sha1};
use clear_on_drop::clear::Clear;
use reqwest::header::UserAgent;
use reqwest::StatusCode;

use std::fs::File;
use std::io::{BufReader, Error};
use std::panic;

pub const USER_AGENT: &str = "checkpwn - cargo utility tool for hibp";

pub enum CheckableChoices {
    ACC,
    PASS,
    PASTE,
}

impl CheckableChoices {
    fn get_api_route(&self) -> &'static str {
        match self {
            CheckableChoices::ACC => "https://haveibeenpwned.com/api/v2/breachedaccount/",
            CheckableChoices::PASS => "https://api.pwnedpasswords.com/range/",
            CheckableChoices::PASTE => "https://haveibeenpwned.com/api/v2/pasteaccount/",
        }
    }
}

pub struct PassArg {
    pub password: String,
}

impl Drop for PassArg {
    fn drop(&mut self) {
        Clear::clear(&mut self.password)
    }
}

/// Format an API request to fit multiple parameters.
fn format_req(
    api_route: &CheckableChoices,
    search_term: &str,
    p3: Option<&str>,
    p4: Option<&str>,
) -> String {
    let mut request = String::from(api_route.get_api_route());
    request.push_str(search_term);

    if let Some(ref path3) = p3 {
        request.push_str("?");
        request.push_str(path3)
    };
    if let Some(ref path4) = p4 {
        request.push_str("&");
        request.push_str(path4)
    };
    request
}

/// Take the user-supplied command-line arugments and make a URL for the HIBP API.
/// If the `pass` argument has been selected, `input_data` needs to be the hashed password.
pub fn arg_to_api_route(arg: &CheckableChoices, input_data: &str) -> String {
    // URL encode the input data when it's a user-supplied argument
    // SHA-1 hashes can safely be passed as-is
    let url_encoded = utf8_percent_encode(input_data, DEFAULT_ENCODE_SET).to_string();

    match arg {
        CheckableChoices::ACC => format_req(
            arg,
            &url_encoded,
            Some("includeUnverified=true"),
            Some("truncateResponse=true"),
        ),
        CheckableChoices::PASS => format_req(
            arg,
            // Only send the first 5 chars to the password range API
            &input_data[..5],
            None,
            None,
        ),
        CheckableChoices::PASTE => format_req(arg, &url_encoded, None, None),
    }
}

/// Take a response from quering password range API and split it into vector of strings.
pub fn split_range(range_string: &str) -> Vec<String> {
    // Split up range_string into vector of strings for each newline
    let mut range_vector: Vec<String> = vec![];
    // Each string truncated to only be the hash, no whitespaces
    // All hashes here have a length of 35, so the useless gets dropped
    range_string
        .lines()
        .for_each(|line| range_vector.push(String::from(&line[..35])));

    range_vector
}

/// Find matching key in recevied set of keys that has been split with `split_range`.
pub fn search_in_range(search_space: Vec<String>, hashed_key: &str) -> bool {
    let mut res = false;

    for hash in search_space {
        // Don't include first five chars of own password, as this also
        // is how the HIBP API returns passwords
        if hash == hashed_key[5..] {
            res = true;
            break;
        }
    }
    res
}

/// Make a breach report based on StatusCode and print result to temrinal.
pub fn breach_report(status_code: StatusCode, searchterm: &str, is_password: bool) -> ((), bool) {
    // Do not display password in terminal
    let request_key = if is_password { "********" } else { searchterm };

    match status_code {
        StatusCode::NotFound => (
            println!(
                "Breach status for {}: {}",
                request_key.cyan(),
                "NO BREACH FOUND".green()
            ),
            false,
        ),
        StatusCode::Ok => (
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
        (StatusCode::NotFound, StatusCode::NotFound) => {
            breach_report(StatusCode::NotFound, &search_key, false)
        }
        // BadRequest allowed here because the account API lets you search for usernames
        // and the paste API will reutrn BadRequest on those
        (StatusCode::NotFound, StatusCode::BadRequest) => {
            breach_report(StatusCode::NotFound, &search_key, false)
        }
        (StatusCode::BadRequest, StatusCode::BadRequest) => {
            set_checkpwn_panic!(errors::BAD_RESPONSE_ERROR);
            panic!();
        }
        // Since the account API both takes username and emails and situation where BadRequest
        // and NotFound are returned should never occur.
        (StatusCode::BadRequest, StatusCode::NotFound) => {
            set_checkpwn_panic!(errors::BAD_RESPONSE_ERROR);
            panic!();
        }
        (StatusCode::BadRequest, StatusCode::Ok) => {
            set_checkpwn_panic!(errors::BAD_RESPONSE_ERROR);
            panic!();
        }
        _ => breach_report(StatusCode::Ok, &search_key, false),
    }
}

/// HIBP breach request used for `acc` arguments.
pub fn acc_breach_request(searchterm: &str) -> () {
    let client = reqwest::Client::new();

    set_checkpwn_panic!(errors::NETWORK_ERROR);

    let acc_stat = client
        .get(&arg_to_api_route(&CheckableChoices::ACC, searchterm))
        .header(UserAgent::new(USER_AGENT))
        .send()
        .unwrap();
    let paste_stat = client
        .get(&arg_to_api_route(&CheckableChoices::ACC, searchterm))
        .header(UserAgent::new(USER_AGENT))
        .send()
        .unwrap();

    evaluate_acc_breach(acc_stat.status(), paste_stat.status(), searchterm);
}

/// Read file into buffer.
pub fn read_file(path: &str) -> Result<BufReader<File>, Error> {
    set_checkpwn_panic!(errors::READ_FILE_ERROR);

    let file_path = File::open(path).unwrap();
    let file = BufReader::new(file_path);

    Ok(file)
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
fn test_evaluate_breach_good() {
    let (_, ok_ok) = evaluate_acc_breach(StatusCode::Ok, StatusCode::Ok, "search_key");
    let (_, ok_notfound) = evaluate_acc_breach(StatusCode::Ok, StatusCode::NotFound, "search_key");
    let (_, notfound_ok) = evaluate_acc_breach(StatusCode::NotFound, StatusCode::Ok, "search_key");
    let (_, ok_badrequest) =
        evaluate_acc_breach(StatusCode::Ok, StatusCode::BadRequest, "search_key");
    let (_, notfound_badrequest) =
        evaluate_acc_breach(StatusCode::NotFound, StatusCode::BadRequest, "search_key");
    let (_, notfound_notfound) =
        evaluate_acc_breach(StatusCode::NotFound, StatusCode::NotFound, "search_key");

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
    let _badrequest_badrequest =
        evaluate_acc_breach(StatusCode::BadRequest, StatusCode::BadRequest, "search_key");
}

#[test]
#[should_panic]
fn test_evaluate_breach_panic_2() {
    let _badrequest_notfound =
        evaluate_acc_breach(StatusCode::BadRequest, StatusCode::NotFound, "search_key");
}

#[test]
#[should_panic]
fn test_evaluate_breach_panic_3() {
    let _badrequest_ok = evaluate_acc_breach(StatusCode::BadRequest, StatusCode::Ok, "search_key");
}

#[test]
fn test_make_req_and_arg_to_route() {
    // API paths taken from https://haveibeenpwned.com/API/v2
    let first_path = format_req(&CheckableChoices::ACC, "test@example.com", None, None);
    let second_path = format_req(
        &CheckableChoices::ACC,
        "test@example.com",
        Some("includeUnverified=true"),
        None,
    );
    let third_path = format_req(
        &CheckableChoices::ACC,
        "test@example.com",
        Some("includeUnverified=true"),
        Some("truncateResponse=true"),
    );

    assert_eq!(
        first_path,
        "https://haveibeenpwned.com/api/v2/breachedaccount/test@example.com"
    );
    assert_eq!(
        second_path,
        "https://haveibeenpwned.com/api/v2/breachedaccount/test@example.com?includeUnverified=true"
    );
    assert_eq!(third_path, "https://haveibeenpwned.com/api/v2/breachedaccount/test@example.com?includeUnverified=true&truncateResponse=true");

    assert_eq!(
        third_path,
        arg_to_api_route(&CheckableChoices::ACC, "test@example.com")
    );
    assert_eq!(
        "https://api.pwnedpasswords.com/range/B1B37",
        arg_to_api_route(&CheckableChoices::PASS, &hash_password("qwerty"))
    );
    assert_eq!(
        "https://haveibeenpwned.com/api/v2/pasteaccount/test@example.com",
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
    breach_report(StatusCode::Forbidden, "saome", true);
}

#[test]
fn test_split_in_range() {
    // From https://api.pwnedpasswords.com/range/21BD1
    let response = String::from(
        "0018A45C4D1DEF81644B54AB7F969B88D65:1
00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2
011053FD0102E94D6AE2F8B83D76FAF94F6:1
012A7CA357541F0AC487871FEEC1891C49C:2
0136E006E24E7D152139815FB0FC6A50B15:3
01A85766CD276B17DE6DA022AA3CADAC3CE:3
024067E46835A540D6454DF5D1764F6AA63:3
02551CADE5DDB7F0819C22BFBAAC6705182:1
025B243055753383B479EF34B44B562701D:2
02A56D549B5929D7CD58EEFA97BFA3DDDB3:8
02F1C470B30D5DDFF9E914B90D35AB7A38F:3
03052B53A891BDEA802D11691B9748C12DC:6
041F514246F050C31B6B5B36CD626C398CA:1
043542C12858C639D087F8F500BCDA56267:4
044768D0FA7FFF8A0E83B45429D483FF243:1",
    );

    let expected = String::from(
        "0018A45C4D1DEF81644B54AB7F969B88D65
00D4F6E8FA6EECAD2A3AA415EEC418D38EC
011053FD0102E94D6AE2F8B83D76FAF94F6
012A7CA357541F0AC487871FEEC1891C49C
0136E006E24E7D152139815FB0FC6A50B15
01A85766CD276B17DE6DA022AA3CADAC3CE
024067E46835A540D6454DF5D1764F6AA63
02551CADE5DDB7F0819C22BFBAAC6705182
025B243055753383B479EF34B44B562701D
02A56D549B5929D7CD58EEFA97BFA3DDDB3
02F1C470B30D5DDFF9E914B90D35AB7A38F
03052B53A891BDEA802D11691B9748C12DC
041F514246F050C31B6B5B36CD626C398CA
043542C12858C639D087F8F500BCDA56267
044768D0FA7FFF8A0E83B45429D483FF243",
    );

    let excp_vec: Vec<_> = expected.lines().collect();

    assert_eq!(split_range(&response), excp_vec);
}

#[test]
fn test_search_succes_and_failure() {
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

    assert_eq!(
        search_in_range(split_range(&contains_pass), &hashed_password),
        true
    );
    assert_eq!(
        search_in_range(split_range(&no_pass), &hashed_password),
        false
    );
}
