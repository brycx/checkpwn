#[cfg(test)]
extern crate assert_cmd;
extern crate clear_on_drop;
extern crate reqwest;
extern crate rpassword;
pub mod api;

#[cfg(test)]
use assert_cmd::prelude::*;
use clear_on_drop::clear::Clear;
use reqwest::header::UserAgent;
use reqwest::StatusCode;
use std::io::BufRead;
#[cfg(test)]
use std::process::Command;
use std::{env, thread, time};

fn main() {
    let argvs: Vec<String> = env::args().collect();
    if argvs.len() >= 2 {
        ()
    } else {
        panic!(api::USAGE_INFO);
    }

    let option_arg = argvs[1].to_lowercase();

    let mut data_search: String;

    match &option_arg as &str {
        api::ACCOUNT => {
            if argvs.len() != 3 {
                panic!(api::USAGE_INFO);
            }
            data_search = argvs[2].to_owned();
        }
        api::PASSWORD => {
            if argvs.len() != 2 {
                panic!(api::USAGE_INFO);
            }
            data_search = rpassword::prompt_password_stdout("Password: ").unwrap();
        }
        _ => panic!(api::USAGE_INFO),
    };

    if option_arg == api::ACCOUNT {
        // Check if user wants to check a local list
        if data_search.to_owned().ends_with(".ls") {
            let file = api::read_file(&data_search).unwrap();

            for line_iter in file.lines() {
                let line = api::strip_white_new(&line_iter.unwrap());

                match line.as_str() {
                    "\n" => continue,
                    "\t" => continue,
                    "" => continue,
                    _ => (),
                };
                api::breach_request(&line, &option_arg);
            }
        } else {
            api::breach_request(&data_search, &option_arg);
        }
    } else if option_arg == api::PASSWORD {
        let client = reqwest::Client::new();

        let mut hashed_password = api::hash_password(&data_search);
        let mut uri_acc = api::arg_to_api_route(&option_arg, &hashed_password);
        let mut pass_stat = client
            .get(&uri_acc)
            .header(UserAgent::new(api::USER_AGENT))
            .send()
            .expect("FAILED TO SEND PASS CLIENT REQUEST");

        let pass_body: String = pass_stat.text().expect("COULD NOT GET PASS RESPONSE BODY");
        let breach_bool = api::search_in_range(
            api::split_range(pass_body),
            &hashed_password,
        );

        if breach_bool {
            api::breach_report(pass_stat.status(), &data_search, true);
        } else {
            api::breach_report(StatusCode::NotFound, &data_search, true);
        }

        // Zero out uri_acc as this contains a weakly hashed password
        Clear::clear(&mut uri_acc);
        Clear::clear(&mut hashed_password);
    }

    // Zero out the data_search argument, especially important if this was a password
    Clear::clear(&mut data_search);

    // Only one request every 1500 miliseconds from any given IP
    thread::sleep(time::Duration::from_millis(1600));
}

#[test]
fn test_cli_acc_breach() {
    let res = Command::new("cargo")
        .args(&["run", "acc", "test@example.com"])
        .unwrap();

    assert!(String::from_utf8_lossy(&res.stdout).contains("BREACH FOUND"));
    assert_eq!(
        String::from_utf8_lossy(&res.stdout).contains("NO BREACH FOUND"),
        false
    );
}

#[test]
fn test_cli_acc_no_breach() {
    let res = Command::new("cargo")
        .args(&["run", "acc", "fsrEos7s@wZ3zdGxr.com"])
        .unwrap();

    assert!(String::from_utf8_lossy(&res.stdout).contains("NO BREACH FOUND"));
}

#[test]
#[should_panic]
fn test_cli_arg_fail() {
    Command::new("cargo")
        .args(&["run", "wrong", "test@example.com"])
        .unwrap()
        .assert()
        .failure();
}

#[test]
fn test_cli_arg_ok() {
    Command::new("cargo")
        .args(&["run", "acc", "test@example.com"])
        .unwrap()
        .assert()
        .success();
}
