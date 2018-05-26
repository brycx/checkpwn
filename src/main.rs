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


struct ApiRoutes {
    email_route: String,
    password_route: String,
}

struct Query {
    include_unverified: String,
    truncate_response: String,
    password_is_sha1: String,
}

fn make_req(p1: &str, p2: &str, p3: Option<&str>, p4: Option<&str>) -> String {

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

fn hash_password(password: &str) -> String {

    let mut shadig = sha1::Sha1::new();
    shadig.update(password.as_bytes());
    shadig.digest().to_string()

}


fn main() {

    let mut core = Core::new().expect("Failed to initialize Tokio core");
    let client = Client::configure()
        .connector(HttpsConnector::new(4, &core.handle()).expect("Failed to set HTTPS as hyper connector"))
        .build(&core.handle());

    let hibp_api = ApiRoutes {
        email_route: String::from("https://haveibeenpwned.com/api/v2/breachedaccount/"),
        password_route: String::from("https://api.pwnedpasswords.com/pwnedpassword/"),
    };

    let hibp_queries = Query {
        include_unverified: String::from("includeUnverified=true"),
        truncate_response: String::from("truncateResponse=true"),
        password_is_sha1: String::from("originalPasswordIsAHash=true"),
    };

    let argvs: Vec<String> = env::args().collect();
    assert_eq!(argvs.len(), 3);

    let option_arg = &argvs[1].to_lowercase();
    let data_search = &argvs[2].to_lowercase();

    let email_option = String::from("email");
    let password_option = String::from("pass");
    let password_option_sha = String::from("sha1pass");

    let url: hyper::Uri;

    if option_arg.to_owned() == email_option {
        url = make_req(
            &hibp_api.email_route,
            &data_search,
            Some(&hibp_queries.include_unverified),
            Some(&hibp_queries.truncate_response)
        ).parse().expect("Failed to parse URL");
    } else if option_arg.to_owned() == password_option {
        url = make_req(
            &hibp_api.password_route,
            &hash_password(&data_search),
            None,
            None
        ).parse().expect("Failed to parse URL");
    } else if option_arg.to_owned() == password_option_sha {
        url = make_req(
            &hibp_api.password_route,
            &hash_password(&data_search),
            Some(&hibp_queries.password_is_sha1),
            None
        ).parse().expect("Failed to parse URL");
    } else { panic!("Invalid option {}", option_arg) }

    let mut requester: Request = Request::new(Method::Get, url);
    requester.headers_mut().set(UserAgent::new("checkpwn - cargo utility tool for HIBP"));

    let work = client.request(requester).and_then(|res| {

        let response = res.status();

        res.body().concat2().and_then(move |body| {
            // Return breach status
            match response {
                StatusCode::NotFound => {
                    println!("Breach status: {}", "NO BREACH FOUND".green());
                },
                StatusCode::Ok => {
                    println!("Breach status: {}", "BREACH FOUND".red());
                    // Only list of breached sites get sent when using
                    // email, not with password.
                    if option_arg.to_owned() == email_option {
                        let v: Value = serde_json::from_slice(&body).unwrap();
                        let mut breached_sites = String::new();

                        for index in 0..v.as_array().unwrap().len() {
                            let site = v[index].get("Name").unwrap();
                            breached_sites.push_str(site.as_str().unwrap());
                            breached_sites.push_str(", ");
                        }

                        println!("Breach(es) happened at: {}", breached_sites);
                    }
                },
                _ => ()
            };
            Ok(())
        })
    });

    core.run(work).expect("Failed to initialize Tokio core");
}
