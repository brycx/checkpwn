#[cfg(test)]
extern crate assert_cmd;
extern crate reqwest;
extern crate rpassword;
pub mod api;

#[cfg(test)]
use assert_cmd::prelude::*;
use reqwest::header::UserAgent;
use reqwest::StatusCode;
use std::io::BufRead;
#[cfg(test)]
use std::process::Command;
use std::{env, thread, time};

fn main() {
    let argvs: Vec<String> = env::args().collect();
    if argvs.len() > 3 || argvs.len() < 2 {
        panic!("Usage: checkpwn acc test@example.com");
    }

    let option_arg = argvs[1].to_lowercase();

    let data_search: String;

    match &option_arg as &str {
        api::ACCOUNT => {
            data_search = argvs[2].to_owned();
        }
        api::PASSWORD => {
            data_search = rpassword::prompt_password_stdout("Password: ").unwrap();
        }
        _ => panic!("Usage: checkpwn acc test@example.com"),
    };

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
            // Only one request every 1500 miliseconds from any given IP
            thread::sleep(time::Duration::from_millis(1600));
        }
    } else if option_arg == api::ACCOUNT {
        api::breach_request(&data_search, &option_arg);
        // Only one request every 1500 miliseconds from any given IP
        thread::sleep(time::Duration::from_millis(1600));
    } else if option_arg == api::PASSWORD {
        let client = reqwest::Client::new();
        let uri_acc = api::arg_to_api_route(&option_arg, &data_search);
        let mut pass_stat = client
            .get(&uri_acc)
            .header(UserAgent::new("checkpwn - cargo utility tool for hibp"))
            .send()
            .unwrap();

        let status_code = pass_stat.status();
        let pass_body = pass_stat.text().unwrap();
        let breach_bool = api::search_in_range(
            api::split_range(&pass_body.as_bytes().to_vec()),
            &data_search,
        );

        if breach_bool {
            api::breach_report(status_code, &data_search, true);
        } else {
            api::breach_report(StatusCode::NotFound, &data_search, true);
        }
    }
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
