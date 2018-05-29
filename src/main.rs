extern crate futures;
extern crate hyper;
extern crate hyper_tls;
extern crate tokio_core;
extern crate colored;
extern crate sha1;
#[cfg(test)]
extern crate assert_cli;

use std::io::{BufReader, BufRead, Error};
use std::fs::File;
use std::{thread, time, env};
use futures::{Future, Stream};
use tokio_core::reactor::Core;
use hyper::{Client, Request, Method, StatusCode, Chunk};
use hyper::header::UserAgent;
use hyper_tls::HttpsConnector;
use colored::*;


struct ApiRoutes {
    acc_route: String,
    password_route: String,
    paste_route: String,
}

struct Query {
    include_unverified: String,
    truncate_response: String,
    password_is_sha1: String,
}

static ACCOUNT: &'static str = "acc";
static PASSWORD: &'static str = "pass";
static PASSWORD_SHA1: &'static str = "sha1pass";

fn arg_to_api_route(arg: String, input_data: String) -> hyper::Uri {

    let hibp_api = ApiRoutes {
        acc_route: String::from("https://haveibeenpwned.com/api/v2/breachedaccount/"),
        password_route: String::from("https://api.pwnedpasswords.com/range/"),
        paste_route: String::from("https://haveibeenpwned.com/api/v2/pasteaccount/"),
    };

    let hibp_queries = Query {
        include_unverified: String::from("includeUnverified=true"),
        truncate_response: String::from("truncateResponse=true"),
        password_is_sha1: String::from("originalPasswordIsAHash=true"),
    };

    let uri: hyper::Uri;

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
    } else if arg == PASSWORD_SHA1 {
        uri = format_req(
            &hibp_api.password_route,
            &hash_password(&input_data)[..5],
            Some(&hibp_queries.password_is_sha1),
            None
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
fn format_req(p1: &str, p2: &str, p3: Option<&str>, p4: Option<&str>) -> hyper::Uri {

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

    request.parse().expect("Failed to parse URL")
}

/// Return SHA1 digest of string.
fn hash_password(password: &str) -> String {

    let mut shadig = sha1::Sha1::new();
    shadig.update(password.as_bytes());
    shadig.digest().to_string().to_uppercase()

}

/// Make a breach report based on StatusCode and print result.
fn breach_report(status_code: hyper::StatusCode, searchterm: String) {
    
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

/// Read file into buffer.
fn read_file(path: &str) -> Result<BufReader<File>, Error> {

    let file_path = File::open(path).unwrap();
    let file = BufReader::new(file_path);

    Ok(file)
}

/// Take hyper::Response from quering password range API and split i into vector of strings.
fn split_range(response: &[u8]) ->  Vec<String> {

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
fn search_in_range(search_space: Vec<String>, search_key: String) -> bool {

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
fn evaluate_breach(acc_stat: StatusCode, paste_stat: StatusCode, search_key: String) -> () {
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
fn breach_request(searchterm: &str, option_arg: &str) -> (hyper::Request, hyper::Request) {
    
    // URI for quering password range, or account, API
    let uri = arg_to_api_route(option_arg.to_owned(), searchterm.to_owned());
    let mut requester_acc: Request = Request::new(Method::Get, uri);
    requester_acc.headers_mut().set(UserAgent::new("checkpwn - cargo utility tool for HIBP"));

    // URI for quering paste API
    let uri_paste = arg_to_api_route("paste".to_owned(), searchterm.to_owned());
    let mut requester_paste: Request = Request::new(Method::Get, uri_paste);
    requester_paste.headers_mut().set(UserAgent::new("checkpwn - cargo utility tool for HIBP"));

        
    (requester_acc, requester_paste)
}


fn main() {

    let mut core = Core::new().expect("Failed to initialize Tokio core");
    let client = Client::configure()
        .connector(HttpsConnector::new(4, &core.handle()).expect("Failed to set HTTPS as hyper connector"))
        .build(&core.handle());

    let argvs: Vec<String> = env::args().collect();
    if argvs.len() != 3 {
        panic!("Usage: checkpwn acc test@example.com");
    }

    let option_arg = &argvs[1].to_lowercase();
    let data_search = &argvs[2];

    if data_search.to_owned().ends_with(".ls") {
        
        let file = read_file(data_search).unwrap();

        for line_iter in file.lines() {
            let line = line_iter.unwrap();

            let (requester_acc, requester_paste) = breach_request(&line, option_arg);

            let get_acc = client.request(requester_acc).map(|res| {
                res.status()
            });

            let get_paste = client.request(requester_paste).map(|res| {
                res.status()
            });
        
            let work = get_acc.join(get_paste);
            let (acc_stat, paste_stat) = core.run(work).expect("Failed to run Tokio core");
            // Return breach report
            evaluate_breach(acc_stat, paste_stat, line);

            // Only one request every 1500 miliseconds from any given IP
            thread::sleep(time::Duration::from_millis(1600));       
        }
    }

    else {        

        let (requester_acc, requester_paste) = breach_request(data_search, option_arg);
        
        if option_arg.to_owned() == ACCOUNT {        

            let get_acc = client.request(requester_acc).map(|res| {
                res.status()
            });

            let get_paste = client.request(requester_paste).map(|res| {
                res.status()
            });

            let work = get_acc.join(get_paste);
            let (acc_stat, paste_stat) = core.run(work).expect("Failed to run Tokio core");
            // Return breach report
            evaluate_breach(acc_stat, paste_stat, data_search.to_owned());
        
        } else if option_arg.to_owned() == PASSWORD {
            
            let work = client.request(requester_acc).and_then(|res| {

                let status_code = res.status();
                
                res.body().concat2().and_then(move |body: Chunk| {                    
                    
                    if option_arg.to_owned() == PASSWORD {
                    
                        let breach_bool = search_in_range(split_range(&body.to_vec()), data_search.to_owned());
                        
                        if breach_bool == true {
                            breach_report(status_code, data_search.to_owned());
                        } else { breach_report(StatusCode::NotFound, data_search.to_owned()); }
                    }   
                    
                    Ok(())                
                })
            });

            core.run(work).expect("Failed to run Tokio core");
        }
    }
}


#[test]
fn test_sha1() {
    let hash = hash_password("qwerty");
    assert_eq!(hash, "b1b3773a05c0ed0176787a4f1574ff0075f7521e".to_uppercase());
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

#[test]
fn test_cli_acc() {

    assert_cli::Assert::command(&["cargo", "run", "acc", "test@example.com"])
        .stdout().contains("BREACH FOUND")
        .unwrap();
}

#[test]
#[should_panic]
// Doing the reverse, since I'm unsure how the coloreed module affects this
fn test_cli_acc_fail() {

    assert_cli::Assert::command(&["cargo", "run", "acc", "test@example.com"])
        .stdout().contains("NO BREACH FOUND")
        .unwrap();
}