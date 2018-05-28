extern crate futures;
extern crate hyper;
extern crate hyper_tls;
extern crate tokio_core;
extern crate colored;
extern crate sha1;

use futures::{Future, Stream};
use hyper::{Client, Request, Method, StatusCode, Chunk};
use hyper::header::UserAgent;
use tokio_core::reactor::Core;
use std::env;
use hyper_tls::HttpsConnector;
use colored::*;
use std::io::{BufReader, BufRead, Error};
use std::fs::File;
use std::{thread, time};


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
static ACCOUNT_LIST: &'static str = "acclist";
static PASSWORD: &'static str = "pass";
static PASSWORD_SHA1: &'static str = "sha1pass";
static PASTE: &'static str = "paste";
static PASTE_LIST: &'static str = "pastelist";

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

    let url: hyper::Uri;

    if (arg.to_owned() == ACCOUNT) || (arg.to_owned() == ACCOUNT_LIST) {
        url = make_req(
            &hibp_api.acc_route,
            &input_data,
            Some(&hibp_queries.include_unverified),
            Some(&hibp_queries.truncate_response)
        );
    } else if arg.to_owned() == PASSWORD {
        url = make_req(
            &hibp_api.password_route,
            // Only send the first 5 chars to the range API
            &hash_password(&input_data)[..5],
            None,
            None,
        );
    } else if arg.to_owned() == PASSWORD_SHA1 {
        url = make_req(
            &hibp_api.password_route,
            &hash_password(&input_data),
            Some(&hibp_queries.password_is_sha1),
            None
        );
    } else if (arg.to_owned() == PASTE) || (arg.to_owned() == PASTE_LIST) {
        url = make_req(
            &hibp_api.paste_route,
            &input_data,
            None,
            None,
        );
    } else { panic!("Invalid option {}", arg) }

    url
} 

fn make_req(p1: &str, p2: &str, p3: Option<&str>, p4: Option<&str>) -> hyper::Uri {

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


fn hash_password(password: &str) -> String {

    let mut shadig = sha1::Sha1::new();
    shadig.update(password.as_bytes());
    shadig.digest().to_string().to_uppercase()

}

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

fn read_file(path: &str) -> Result<BufReader<File>, Error> {

    let file_path = File::open(path).unwrap();
    let file = BufReader::new(file_path);

    Ok(file)
}

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

fn search_in_range(search_space: Vec<String>, search_key: String) -> bool {

    let mut res = false;
    let hashed_key = String::from(&hash_password(&search_key)[5..]);

    for index in search_space {
        if index == hashed_key {
            res = true;
        }
    }

    res
}

fn evaluate_breach(acc_stat: StatusCode, paste_stat: StatusCode, search_key: String) -> () {
    // Only if both StatusCodes for a breach report run on sites and pastes is 404, will it
    // return NO BREACH FOUND, else BREACH FOUND 
    match (acc_stat, paste_stat) {
        (StatusCode::NotFound, StatusCode::NotFound) => breach_report(StatusCode::NotFound, search_key),
        _ => breach_report(StatusCode::Ok, search_key)
    }
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
    let data_search = &argvs[2].to_lowercase();

    if data_search.to_owned().ends_with(".ls") {
        
        let file = read_file(data_search).unwrap();

        for line_iter in file.lines() {

            let line = line_iter.unwrap();
            let url = arg_to_api_route(option_arg.to_owned(), line.clone());
            let mut requester: Request = Request::new(Method::Get, url);
            requester.headers_mut().set(UserAgent::new("checkpwn - cargo utility tool for HIBP"));

            let url_2 = arg_to_api_route("paste".to_owned(), line.clone());
            let mut requester_2: Request = Request::new(Method::Get, url_2);
            requester_2.headers_mut().set(UserAgent::new("checkpwn - cargo utility tool for HIBP"));

            let get_acc = client.request(requester).map(|res| {
                res.status()
            });

            let get_paste = client.request(requester_2).map(|res| {
                res.status()
            });
        
            let work = get_acc.join(get_paste);
            let (acc_stat, paste_stat) = core.run(work).expect("Failed to initialize Tokio core");
            // Return breach report
            evaluate_breach(acc_stat, paste_stat, line);

            // Only one request every 1500 miliseconds from any given IP
            thread::sleep(time::Duration::from_millis(1600));       
        }
    }

    else {
        
        let url = arg_to_api_route(option_arg.to_owned(), data_search.to_owned());
        let mut requester: Request = Request::new(Method::Get, url);
        requester.headers_mut().set(UserAgent::new("checkpwn - cargo utility tool for HIBP"));

        let work = client.request(requester).and_then(|res| {

            let status_code = res.status();
                
            res.body().concat2().and_then(move |body: Chunk| {                    
                    
                if option_arg.to_owned() == PASSWORD {
                    
                    let breach_bool = search_in_range(split_range(&body.to_vec()), data_search.to_owned());
                        
                    if breach_bool == true {
                        breach_report(status_code, data_search.to_owned());
                        // If it is false, it's the same as a 404 StatusCode
                    } else { breach_report(StatusCode::NotFound, data_search.to_owned()); }
                }
                    
                Ok(())                
            })
        });
        
        core.run(work).expect("Failed to initialize Tokio core");
    }
}


#[test]
fn test_sha1() {
    let hash = hash_password("qwerty");
    assert_eq!(hash, "b1b3773a05c0ed0176787a4f1574ff0075f7521e");
}

#[test]
fn test_make_req() {

    // API paths taken from https://haveibeenpwned.com/API/v2
    let first_path = make_req(
        "https://haveibeenpwned.com/api/v2/breachedaccount/",
        "test@example.com",
        None,
        None
    );
    let second_path = make_req(
        "https://haveibeenpwned.com/api/v2/breachedaccount/",
        "test@example.com",
        Some("includeUnverified=true"),
        None
    );
    let third_path = make_req(
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