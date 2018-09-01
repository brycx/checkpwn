extern crate colored;
extern crate hex;
extern crate percent_encoding;
extern crate reqwest;
extern crate sha1;

use self::colored::Colorize;
use self::percent_encoding::{utf8_percent_encode, DEFAULT_ENCODE_SET};
use self::sha1::{Digest, Sha1};
use reqwest::header::UserAgent;
use reqwest::StatusCode;
use std::fs::File;
use std::io::{BufReader, Error};

pub const ACCOUNT: &str = "acc";
pub const PASSWORD: &str = "pass";

static ACC_ROUTE: &str = "https://haveibeenpwned.com/api/v2/breachedaccount/";
static PASS_ROUTE: &str = "https://api.pwnedpasswords.com/range/";
static PASTE_ROUTE: &str = "https://haveibeenpwned.com/api/v2/pasteaccount/";

/// Format an API request to fit multiple parameters.
fn format_req(api_route: &str, search_term: &str, p3: Option<&str>, p4: Option<&str>) -> String {
    let mut request = String::from(api_route);
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

/// Take the user-supplied command-line arugments and make a URL for the HIBP API. Also
/// manages a call to the paste API route, which is done automatically on each "acc" call.
pub fn arg_to_api_route(arg: &str, input_data: &str) -> String {
    // URL encode the input data when it's a user-supplied argument
    // SHA-1 hashes can safely be passed as-is
    let url_encoded = utf8_percent_encode(input_data, DEFAULT_ENCODE_SET).to_string();

    match arg {
        ACCOUNT => format_req(
            ACC_ROUTE,
            &url_encoded,
            Some("includeUnverified=true"),
            Some("truncateResponse=true"),
        ),
        PASSWORD => format_req(
            PASS_ROUTE,
            // Only send the first 5 chars to the password range API
            &hash_password(input_data)[..5],
            None,
            None,
        ),
        "paste" => format_req(PASTE_ROUTE, &url_encoded, None, None),
        _ => panic!("Invalid option {}", arg),
    }
}

/// Take a response from quering password range API and split it into vector of strings.
pub fn split_range(response: &[u8]) -> Vec<String> {
    let range_string = String::from_utf8_lossy(response);

    // Split up range_string into vector of strings for each newline
    let range_vector: Vec<_> = range_string.lines().collect();
    let mut final_vec: Vec<_> = vec![];

    // Each string truncated to only be the hash, no whitespaces
    // All hashes here have a length of 35, so the useless gets dropped
    for index in range_vector {
        final_vec.push(String::from(&index[..35]));
    }
    final_vec
}

/// Find matching key in recevied set of keys.
pub fn search_in_range(search_space: Vec<String>, search_key: &str) -> bool {
    let mut res = false;
    let hashed_key = hash_password(search_key);

    for item in search_space {
        // Don't include first five chars of own password, as this also
        // is how the HIBP API returns passwords
        if item == hashed_key[5..] {
            res = true;
            break;
        }
    }

    res
}

/// Make a breach report based on StatusCode and print result.
pub fn breach_report(status_code: StatusCode, searchterm: &str, is_password: bool) -> ((), String) {
    let breach_found = String::from("BREACH FOUND");
    let breach_not_found = String::from("NO BREACH FOUND");
    // Do not display password in terminal
    let request_key = if is_password { "********" } else { searchterm };

    match status_code {
        StatusCode::NotFound => (
            println!(
                "Breach status for {}: {}",
                request_key.cyan(),
                "NO BREACH FOUND".green()
            ),
            breach_not_found,
        ),
        StatusCode::Ok => (
            println!(
                "Breach status for {}: {}",
                request_key.cyan(),
                "BREACH FOUND".red()
            ),
            breach_found,
        ),
        _ => panic!("Unrecognized StatusCode detected"),
    }
}

/// Return a breach report based on two StatusCodes, both need to be false to be a non-breach.
fn evaluate_acc_breach(
    acc_stat: StatusCode,
    paste_stat: StatusCode,
    search_key: &str,
) -> ((), String) {
    let err = "HIBP returned Bad Request on account: ".to_string()
        + search_key
        + " - Make sure it is a valid account.";

    match (acc_stat, paste_stat) {
        (StatusCode::NotFound, StatusCode::NotFound) => {
            breach_report(StatusCode::NotFound, &search_key, false)
        }
        (StatusCode::NotFound, StatusCode::BadRequest) => {
            breach_report(StatusCode::NotFound, &search_key, false)
        }
        (StatusCode::BadRequest, StatusCode::BadRequest) => {
            panic!(err);
        }
        // Since the account API both takes username and emails and situation where BadRequest
        // and NotFound arereturned should never occur.
        (StatusCode::BadRequest, StatusCode::NotFound) => {
            panic!(err);
        }
        (StatusCode::BadRequest, StatusCode::Ok) => {
            panic!(err);
        }
        _ => breach_report(StatusCode::Ok, &search_key, false),
    }
}

/// Make API request for both paste and a command line argument.
pub fn breach_request(searchterm: &str, option_arg: &str) -> () {
    // URI for quering password range, or account, API
    let uri_acc = arg_to_api_route(option_arg, searchterm);
    // URI for quering paste API
    let uri_paste = arg_to_api_route("paste", searchterm);

    let client = reqwest::Client::new();

    let acc_stat = client
        .get(&uri_acc)
        .header(UserAgent::new("checkpwn - cargo utility tool for hibp"))
        .send()
        .unwrap();
    let paste_stat = client
        .get(&uri_paste)
        .header(UserAgent::new("checkpwn - cargo utility tool for hibp"))
        .send()
        .unwrap();

    evaluate_acc_breach(acc_stat.status(), paste_stat.status(), searchterm);
}

/// Read file into buffer.
pub fn read_file(path: &str) -> Result<BufReader<File>, Error> {
    let file_path = File::open(path).expect("FILE NOT FOUND");
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

// Strip all whitespace and all newlines from a given string
pub fn strip_white_new(string: &str) -> String {
    string.replace("\n", "").replace(" ", "").replace("\'", "'")
}

#[test]
fn test_strip_white_new() {
    let string_1 = String::from("fkljjsdjlksfdklj dfiwj wefwefwfe");
    let string_2 = String::from("derbrererer\n");
    let string_3 = String::from("dee\nwfweww   rb  tte rererer\n");

    assert_eq!(
        &strip_white_new(&string_1),
        "fkljjsdjlksfdkljdfiwjwefwefwfe"
    );
    assert_eq!(&strip_white_new(&string_2), "derbrererer");
    assert_eq!(&strip_white_new(&string_3), "deewfwewwrbtterererer");
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

    assert_eq!(ok_ok, "BREACH FOUND");
    assert_eq!(ok_notfound, "BREACH FOUND");
    assert_eq!(notfound_ok, "BREACH FOUND");
    assert_eq!(ok_badrequest, "BREACH FOUND");
    assert_eq!(notfound_badrequest, "NO BREACH FOUND");
    assert_eq!(notfound_notfound, "NO BREACH FOUND");
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
    let first_path = format_req(
        "https://haveibeenpwned.com/api/v2/breachedaccount/",
        "test@example.com",
        None,
        None,
    );
    let second_path = format_req(
        "https://haveibeenpwned.com/api/v2/breachedaccount/",
        "test@example.com",
        Some("includeUnverified=true"),
        None,
    );
    let third_path = format_req(
        "https://haveibeenpwned.com/api/v2/breachedaccount/",
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

    assert_eq!(third_path, arg_to_api_route("acc", "test@example.com"));
    assert_eq!(
        "https://api.pwnedpasswords.com/range/B1B37",
        arg_to_api_route("pass", "qwerty")
    );
    assert_eq!(
        "https://haveibeenpwned.com/api/v2/pasteaccount/test@example.com",
        arg_to_api_route("paste", "test@example.com")
    );
}

#[test]
fn test_good_argument() {
    let option_arg = String::from("acc");
    let data_search = String::from("test@example.com");

    arg_to_api_route(&option_arg, &data_search);
}

#[should_panic]
#[test]
fn test_invalid_argument() {
    let option_arg = String::from("badoption");
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

    assert_eq!(split_range(response.as_bytes()), excp_vec);
}
