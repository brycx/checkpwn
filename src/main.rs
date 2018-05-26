extern crate futures;
extern crate hyper;
extern crate hyper_tls;
extern crate tokio_core;
extern crate colored;
extern crate serde_json;
extern crate sha1;

use futures::{Future, Stream};
use hyper::{Client, Request, Method, StatusCode};
use hyper::header::UserAgent;
use tokio_core::reactor::Core;
use std::env;
use hyper_tls::HttpsConnector;
use colored::*;
use serde_json::Value;
use std::io::{BufReader, BufRead, Error};
use std::fs::File;
use std::{thread, time};


struct ApiRoutes {
    email_route: String,
    password_route: String,
}

struct Query {
    include_unverified: String,
    truncate_response: String,
    password_is_sha1: String,
}

static EMAIL: &'static str = "email";
static EMAIL_LIST: &'static str = "emaillist";
static PASSWORD: &'static str = "pass";
static PASSWORD_SHA1: &'static str = "sha1pass";

fn arg_to_api_route(arg: String, input_data: String) -> hyper::Uri {

    let hibp_api = ApiRoutes {
        email_route: String::from("https://haveibeenpwned.com/api/v2/breachedaccount/"),
        password_route: String::from("https://api.pwnedpasswords.com/pwnedpassword/"),
    };

    let hibp_queries = Query {
        include_unverified: String::from("includeUnverified=true"),
        truncate_response: String::from("truncateResponse=true"),
        password_is_sha1: String::from("originalPasswordIsAHash=true"),
    };

    let url: hyper::Uri;

    if (arg.to_owned() == EMAIL) || (arg.to_owned() == EMAIL_LIST) {
        url = make_req(
            &hibp_api.email_route,
            &input_data,
            Some(&hibp_queries.include_unverified),
            Some(&hibp_queries.truncate_response)
        );
    } else if arg.to_owned() == PASSWORD {
        url = make_req(
            &hibp_api.password_route,
            &hash_password(&input_data),
            None,
            None
        );
    } else if arg.to_owned() == PASSWORD_SHA1 {
        url = make_req(
            &hibp_api.password_route,
            &hash_password(&input_data),
            Some(&hibp_queries.password_is_sha1),
            None
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
    shadig.digest().to_string()

}

fn breach_report(status_code: hyper::StatusCode, opt_argument: &String, resp_body: hyper::Chunk, line: Option<String>) {
    
    let searchterm = match line {
        Some(ref keyword) => keyword,
        None => opt_argument,
    };

    
    match status_code {
        StatusCode::NotFound => {
            println!("Breach status for {}: {}", searchterm.cyan(), "NO BREACH FOUND".green());
        },
        StatusCode::Ok => {
            println!("Breach status for {}: {}", searchterm.cyan(), "BREACH FOUND".red());
            // Only list of breached sites get sent when using
            // email, not with password.
            if (opt_argument.to_owned() == EMAIL) || (opt_argument.to_owned() == EMAIL_LIST) {
                let v: Value = serde_json::from_slice(&resp_body).unwrap();
                let mut breached_sites = String::new();

                for index in 0..v.as_array().unwrap().len() {
                    let site = v[index].get("Name").unwrap();
                    breached_sites.push_str(site.as_str().unwrap());
                    breached_sites.push_str(", ");
                }

                println!("Breach(es) happened at: {}", breached_sites);
            }
        },
        _ => panic!("Unrecognized status code detected")
    }
}

pub fn read_file(path: &str) -> Result<BufReader<File>, Error> {

    let file_path = File::open(path).unwrap();
    let file = BufReader::new(file_path);

    Ok(file)
}

fn main() {

    let mut core = Core::new().expect("Failed to initialize Tokio core");
    let client = Client::configure()
        .connector(HttpsConnector::new(4, &core.handle()).expect("Failed to set HTTPS as hyper connector"))
        .build(&core.handle());

    let argvs: Vec<String> = env::args().collect();
    assert_eq!(argvs.len(), 3);

    let option_arg = &argvs[1].to_lowercase();
    let data_search = &argvs[2].to_lowercase();

    if option_arg.to_owned() == EMAIL_LIST {
        let file = read_file(data_search).unwrap();

        for line_iter in file.lines() {

            let line = line_iter.unwrap();

            let url = arg_to_api_route(option_arg.to_owned(), line.clone());
            
            let mut requester: Request = Request::new(Method::Get, url);
            requester.headers_mut().set(UserAgent::new("checkpwn - cargo utility tool for HIBP"));

            let work = client.request(requester).and_then(|res| {

                let status_code = res.status();

                res.body().concat2().and_then(move |body| {
                    // Return breach status
                    breach_report(status_code, &option_arg, body, Some(line));
            
                    Ok(())
                })
            });

            // Only one request every 1500 miliseconds from any given IP
            thread::sleep(time::Duration::from_millis(1600));
        
            core.run(work).expect("Failed to initialize Tokio core");
        }
    }

    else {
        
        let url = arg_to_api_route(option_arg.to_owned(), data_search.to_owned());
        let mut requester: Request = Request::new(Method::Get, url);
        requester.headers_mut().set(UserAgent::new("checkpwn - cargo utility tool for HIBP"));

        let work = client.request(requester).and_then(|res| {

            let status_code = res.status();

            res.body().concat2().and_then(move |body| {
                // Return breach status
                breach_report(status_code, &option_arg, body, None);
            
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

    let option_arg = String::from("email");
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