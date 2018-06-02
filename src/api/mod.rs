extern crate sha1;
extern crate hex;
extern crate reqwest;
extern crate colored;
pub mod util;

use self::colored::Colorize;
use self::sha1::{Sha1, Digest};
use std::io::{BufReader, Error};
use std::fs::File;
use reqwest::header::UserAgent;
use reqwest::StatusCode;

struct ApiRoutes {
    acc_route: String,
    password_route: String,
    paste_route: String,
}

struct Query {
    include_unverified: String,
    truncate_response: String,
}

pub static ACCOUNT: &'static str = "acc";
pub static PASSWORD: &'static str = "pass";

pub fn arg_to_api_route(arg: String, input_data: String) -> String {

    let hibp_api = ApiRoutes {
        acc_route: String::from("https://haveibeenpwned.com/api/v2/breachedaccount/"),
        password_route: String::from("https://api.pwnedpasswords.com/range/"),
        paste_route: String::from("https://haveibeenpwned.com/api/v2/pasteaccount/"),
    };

    let hibp_queries = Query {
        include_unverified: String::from("includeUnverified=true"),
        truncate_response: String::from("truncateResponse=true"),
    };

    let uri: String;

    if arg == ACCOUNT {
        uri = format_req(
            &hibp_api.acc_route,
            &input_data,
            Some(&hibp_queries.include_unverified),
            Some(&hibp_queries.truncate_response)
        );
    } else if arg == PASSWORD {
        uri = format_req(
            &hibp_api.password_route,
            // Only send the first 5 chars to the range API
            &hash_password(&input_data)[..5],
            None,
            None,
        );
    } else if arg == "paste" {
        uri = format_req(
            &hibp_api.paste_route,
            &input_data,
            None,
            None,
        );
    } else { panic!("Invalid option {}", arg); }

    uri
}

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

/// Take hyper::Response from quering password range API and split i into vector of strings.
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


/// Return a breach report based on two StatusCodes, both need to be false to be a non-breach.
pub fn evaluate_breach(acc_stat: StatusCode, paste_stat: StatusCode, search_key: String) -> () {
    // Only if both StatusCodes for sites and paste is 404, will it
    // return NO BREACH FOUND, else BREACH FOUND
    // Or if the paste request was done using a non-email, then it will be a 400
    match (acc_stat, paste_stat) {
        (StatusCode::NotFound, StatusCode::NotFound) => { breach_report(StatusCode::NotFound, search_key); },
        (StatusCode::NotFound, StatusCode::BadRequest) => { breach_report(StatusCode::NotFound, search_key); },
        _ => { breach_report(StatusCode::Ok, search_key); }
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
    
    evaluate_breach(acc_stat.status(), paste_stat.status(), searchterm.to_owned())
}

/// Make a breach report based on StatusCode and print result.
pub fn breach_report(status_code: StatusCode, searchterm: String) {
    
    match status_code {
        StatusCode::NotFound => {
            println!("Breach status for {}: {}", searchterm.cyan(), "NO BREACH FOUND".green());
        },
        StatusCode::Ok => {
            println!("Breach status for {}: {}", searchterm.cyan(), "BREACH FOUND".red());
        },
        _ => panic!("Unrecognized status code detected")
    }
}


#[test]
fn test_make_req() {

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

#[test]
fn test_sha1() {
    let hash = hash_password("qwerty");
    assert_eq!(hash, "b1b3773a05c0ed0176787a4f1574ff0075f7521e".to_uppercase());
}