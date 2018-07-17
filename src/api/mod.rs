extern crate sha1;
extern crate hex;
extern crate reqwest;
extern crate colored;

use self::colored::Colorize;
use self::sha1::{Sha1, Digest};
use std::io::{BufReader, Error};
use std::fs::File;
use reqwest::header::UserAgent;
use reqwest::StatusCode;

pub const ACCOUNT: &'static str = "acc";
pub const PASSWORD: &'static str = "pass";

/// Format an API request to fit multiple parameters
pub fn format_req(p1: &str, p2: &str, p3: Option<&str>, p4: Option<&str>) -> String {

    let mut request = String::new();

    request.push_str(p1);
    request.push_str(p2);

    match p3 {
        Some(ref path3) => {
            request.push_str("?");
            request.push_str(path3)
        },
        None => (),
    };

    match p4 {
        Some(ref path4) => {
            request.push_str("&");
            request.push_str(path4)
        },
        None => (),
    };

    request
}

/// Take the user supplied command line arugments and make a url for the HIBP API.
pub fn arg_to_api_route(arg: String, input_data: String) -> String {

    let acc_route = String::from("https://haveibeenpwned.com/api/v2/breachedaccount/");
    let password_route = String::from("https://api.pwnedpasswords.com/range/");
    let paste_route = String::from("https://haveibeenpwned.com/api/v2/pasteaccount/");

    let include_unverified = String::from("includeUnverified=true");
    let truncate_response = String::from("truncateResponse=true");

    match &arg as &str {
        ACCOUNT => {
            format_req(
                &acc_route,
                &input_data,
                Some(&include_unverified),
                Some(&truncate_response))
        },
        PASSWORD => {
            format_req(
                &password_route,
                // Only send the first 5 chars to the range API
                &hash_password(&input_data)[..5],
                None,
                None)
        },
        "paste" => {
            format_req(
                &paste_route,
                &input_data,
                None,
                None)
        },
        _ => { panic!("Invalid option {}", arg) }
    }
}

/// Take a response from quering password range API and split i into vector of strings.
pub fn split_range(response: &[u8]) ->  Vec<String> {

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


/// Find matching key in recevied set of keys
pub fn search_in_range(search_space: Vec<String>, search_key: String) -> bool {

    let mut res = false;
    // Don't include first five chars of own password, as this also
    // is how the HIBP API returns passwords
    let hashed_key = String::from(&hash_password(&search_key)[5..]);

    for index in search_space {
        if index == hashed_key {
            res = true;
        }
    }

    res
}

/// Make a breach report based on StatusCode and print result.
pub fn breach_report(status_code: StatusCode, searchterm: String) -> ((), String) {

    let breach_found = String::from("BREACH FOUND");
    let breach_not_found = String::from("NO BREACH FOUND");

    match status_code {
        StatusCode::NotFound => {
            (println!("Breach status for {}: {}", searchterm.cyan(), "NO BREACH FOUND".green()),
            breach_not_found)
        },
        StatusCode::Ok => {
            (println!("Breach status for {}: {}", searchterm.cyan(), "BREACH FOUND".red()),
            breach_found)
        },
        _ => panic!("Unrecognized status code detected")
    }
}

/// Return a breach report based on two StatusCodes, both need to be false to be a non-breach.
pub fn evaluate_breach(acc_stat: StatusCode, paste_stat: StatusCode, search_key: String) -> ((), String) {

    let err = "HIBP returned Bad Request on account: ".to_string() + &search_key + " - Make sure it is a valid account.";

    match (acc_stat, paste_stat) {
        (StatusCode::NotFound, StatusCode::NotFound) => { breach_report(StatusCode::NotFound, search_key) },
        (StatusCode::NotFound, StatusCode::BadRequest) => { breach_report(StatusCode::NotFound, search_key) },
        (StatusCode::BadRequest, StatusCode::BadRequest) => { panic!(err); },
        // Since the account API both takes username and emails and situation where BadRequest and NotFound are
        // returned should never occur.
        (StatusCode::BadRequest, StatusCode::NotFound) => { panic!(err); },
        (StatusCode::BadRequest, StatusCode::Ok) => { panic!(err); },
        _ => { breach_report(StatusCode::Ok, search_key) }
    }
}

/// Make API request for both paste and a command line argument.
pub fn breach_request(searchterm: &str, option_arg: &str) -> () {

    // URI for quering password range, or account, API
    let uri_acc = arg_to_api_route(option_arg.to_owned(), searchterm.to_owned());
    // URI for quering paste API
    let uri_paste = arg_to_api_route("paste".to_owned(), searchterm.to_owned());

    let client = reqwest::Client::new();

    let acc_stat = client.get(&uri_acc)
        .header(UserAgent::new("checkpwn - cargo utility tool for hibp"))
        .send().unwrap();
    let paste_stat = client.get(&uri_paste)
        .header(UserAgent::new("checkpwn - cargo utility tool for hibp"))
        .send().unwrap();

    evaluate_breach(acc_stat.status(), paste_stat.status(), searchterm.to_owned());
}

/// Read file into buffer.
pub fn read_file(path: &str) -> Result<BufReader<File>, Error> {

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

// Strip all whitespace and all newlines from a given string
pub fn strip_white_new(string: String) -> String {
    string.replace("\n", "").replace(" ", "").replace("\'", "'")
}

#[test]
fn test_strip_white_new() {
    let string_1 = String::from("fkljjsdjlksfdklj dfiwj wefwefwfe");
    let string_2 = String::from("derbrererer\n");
    let string_3 = String::from("dee\nwfweww   rb  tte rererer\n");

    assert_eq!(&strip_white_new(string_1), "fkljjsdjlksfdkljdfiwjwefwefwfe");
    assert_eq!(&strip_white_new(string_2), "derbrererer");
    assert_eq!(&strip_white_new(string_3), "deewfwewwrbtterererer");
}


#[test]
fn test_sha1() {
    let hash = hash_password("qwerty");
    assert_eq!(hash, "b1b3773a05c0ed0176787a4f1574ff0075f7521e".to_uppercase());
}

#[test]
fn test_evaluate_breach_good() {

    let (_, ok_ok) = evaluate_breach(StatusCode::Ok, StatusCode::Ok, "search_key".to_owned());
    let (_, ok_notfound) = evaluate_breach(StatusCode::Ok, StatusCode::NotFound, "search_key".to_owned());
    let (_, notfound_ok) = evaluate_breach(StatusCode::NotFound, StatusCode::Ok, "search_key".to_owned());
    let (_, ok_badrequest) = evaluate_breach(StatusCode::Ok, StatusCode::BadRequest, "search_key".to_owned());
    let (_, notfound_badrequest) = evaluate_breach(StatusCode::NotFound, StatusCode::BadRequest, "search_key".to_owned());
    let (_, notfound_notfound) = evaluate_breach(StatusCode::NotFound, StatusCode::NotFound, "search_key".to_owned());

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
    let _badrequest_badrequest = evaluate_breach(StatusCode::BadRequest, StatusCode::BadRequest, "search_key".to_owned());
}

#[test]
#[should_panic]
fn test_evaluate_breach_panic_2() {
    let _badrequest_notfound = evaluate_breach(StatusCode::BadRequest, StatusCode::NotFound, "search_key".to_owned());
}

#[test]
#[should_panic]
fn test_evaluate_breach_panic_3() {
    let _badrequest_ok = evaluate_breach(StatusCode::BadRequest, StatusCode::Ok, "search_key".to_owned());
}

#[test]
fn test_make_req_and_arg_to_route() {

    // API paths taken from https://haveibeenpwned.com/API/v2
    let first_path = format_req(
        "https://haveibeenpwned.com/api/v2/breachedaccount/",
        "test@example.com",
        None,
        None
    );
    let second_path = format_req(
        "https://haveibeenpwned.com/api/v2/breachedaccount/",
        "test@example.com",
        Some("includeUnverified=true"),
        None
    );
    let third_path = format_req(
        "https://haveibeenpwned.com/api/v2/breachedaccount/",
        "test@example.com",
        Some("includeUnverified=true"),
        Some("truncateResponse=true")
    );

    assert_eq!(first_path, "https://haveibeenpwned.com/api/v2/breachedaccount/test@example.com");
    assert_eq!(second_path, "https://haveibeenpwned.com/api/v2/breachedaccount/test@example.com?includeUnverified=true");
    assert_eq!(third_path, "https://haveibeenpwned.com/api/v2/breachedaccount/test@example.com?includeUnverified=true&truncateResponse=true");

    assert_eq!(third_path, arg_to_api_route("acc".to_owned(), "test@example.com".to_owned()));
    assert_eq!("https://api.pwnedpasswords.com/range/B1B37", arg_to_api_route("pass".to_owned(), "qwerty".to_owned()));
    assert_eq!("https://haveibeenpwned.com/api/v2/pasteaccount/test@example.com", arg_to_api_route("paste".to_owned(), "test@example.com".to_owned()));
}

#[test]
fn test_good_argument() {

    let option_arg = String::from("acc");
    let data_search = String::from("test@example.com");

    arg_to_api_route(option_arg, data_search);

}

#[should_panic]
#[test]
fn test_invalid_argument() {

    let option_arg = String::from("badoption");
    let data_search = String::from("test@example.com");

    arg_to_api_route(option_arg, data_search);

}
