// MIT License

// Copyright (c) 2018 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#[cfg(test)]
extern crate assert_cmd;
extern crate clear_on_drop;
extern crate reqwest;
extern crate rpassword;
#[macro_use]
pub mod api;

#[cfg(test)]
use assert_cmd::prelude::*;
use clear_on_drop::clear::Clear;
use reqwest::header;
use reqwest::StatusCode;
use std::io::BufRead;
use std::panic;
#[cfg(test)]
use std::process::Command;
use std::{env, thread, time};

fn acc_check(data_search: &str) {
    // Check if user wants to check a local list
    if data_search.ends_with(".ls") {
        set_checkpwn_panic!(api::errors::BUFREADER_ERROR);
        let file = api::read_file(data_search).unwrap();

        for line_iter in file.lines() {
            set_checkpwn_panic!(api::errors::READLINE_ERROR);
            let line = api::strip(&line_iter.unwrap());
            if line.is_empty() {
                continue;
            }
            api::acc_breach_request(&line);
            // Only one request every 1500 miliseconds from any given IP
            thread::sleep(time::Duration::from_millis(1600));
        }
    } else {
        api::acc_breach_request(data_search);
    }
}

fn pass_check(data_search: &api::PassArg) {
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::USER_AGENT,
        header::HeaderValue::from_static(api::CHECKPWN_USER_AGENT),
    );

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap();

    let mut hashed_password = api::hash_password(&data_search.password);
    let mut uri_acc = api::arg_to_api_route(&api::CheckableChoices::PASS, &hashed_password);
    set_checkpwn_panic!(api::errors::NETWORK_ERROR);
    let mut pass_stat = client.get(&uri_acc).send().unwrap();

    set_checkpwn_panic!(api::errors::DECODING_ERROR);
    let pass_body: String = pass_stat.text().unwrap();

    if api::search_in_range(&pass_body, &hashed_password) {
        api::breach_report(pass_stat.status(), "", true);
    } else {
        api::breach_report(StatusCode::NOT_FOUND, "", true);
    }

    // Zero out as this contains a weakly hashed password
    Clear::clear(&mut uri_acc);
    Clear::clear(&mut hashed_password);
}

fn main() {
    // Set custom usage panic message
    set_checkpwn_panic!(api::errors::USAGE_ERROR);
    assert!(env::args().len() >= 2);
    assert!(env::args().len() < 4);

    let mut argvs: Vec<String> = env::args().collect();

    match argvs[1].to_lowercase().as_str() {
        "acc" => {
            assert!(argvs.len() == 3);
            acc_check(&argvs[2]);
        }
        "pass" => {
            assert!(argvs.len() == 2);
            set_checkpwn_panic!(api::errors::PASSWORD_ERROR);
            let password = api::PassArg {
                password: rpassword::prompt_password_stdout("Password: ").unwrap(),
            };
            pass_check(&password);
        }
        _ => panic!(),
    };
    // Zero out the collected arguments, in case the user accidentally inputs sensitive info
    for argument in &mut argvs.iter_mut() {
        Clear::clear(&mut *argument);
    }
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
#[should_panic]
fn test_cli_arg_fail_2() {
    Command::new("cargo")
        .args(&["run"])
        .unwrap()
        .assert()
        .failure();
}

#[test]
#[should_panic]
fn test_cli_arg_fail_3() {
    Command::new("cargo")
        .args(&["run", "wrong", "test@example.com", "too much"])
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
