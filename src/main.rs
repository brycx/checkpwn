#[cfg(test)]
extern crate assert_cmd;
extern crate reqwest;
extern crate rpassword;
extern crate clear_on_drop;
pub mod api;

#[cfg(test)]
use assert_cmd::prelude::*;
use reqwest::header::UserAgent;
use reqwest::StatusCode;
use std::io::BufRead;
#[cfg(test)]
use std::process::Command;
use std::{env, thread, time};
use clear_on_drop::clear::Clear;

fn usage_panic() {
    panic!("Usage: checkpwn acc test@example.com");
}

fn main() {
    let argvs: Vec<String> = env::args().collect();
    if argvs.len() >= 2 {
        ()
    } else {
        usage_panic();
    }

    let option_arg = argvs[1].to_lowercase();

    let mut data_search: String;

    match &option_arg as &str {
        api::ACCOUNT => {
            if argvs.len() != 3 {usage_panic();}
            data_search = argvs[2].to_owned();
        }
        api::PASSWORD => {
            if argvs.len() != 2 {usage_panic();}
            data_search = rpassword::prompt_password_stdout("Password: ").unwrap();
        }
        _ => panic!("Usage: checkpwn acc test@example.com"),
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
            .header(UserAgent::new("checkpwn - cargo utility tool for hibp"))
            .send()
            .expect("FAILED TO SEND PASS CLIENT REQUEST");

        let status_code = pass_stat.status();
        let pass_body = pass_stat.text().unwrap();
        let breach_bool = api::search_in_range(
            api::split_range(&pass_body.as_bytes().to_vec()),
            &hashed_password,
        );

        if breach_bool {
            api::breach_report(status_code, &data_search, true);
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
