// MIT License

// Copyright (c) 2018-2020 brycx

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
mod config;

#[cfg(test)]
extern crate assert_cmd;
extern crate reqwest;
extern crate rpassword;
extern crate serde;
extern crate zeroize;

#[macro_use]
pub mod api;

#[cfg(test)]
use assert_cmd::prelude::*;
use reqwest::blocking::Client;
use reqwest::header;
use reqwest::StatusCode;
use std::io::{stdin, BufRead};
use std::panic;
#[cfg(test)]
use std::process::Command;
use std::{env, thread, time};
use zeroize::Zeroize;

fn acc_check(data_search: &str) {
    set_checkpwn_panic!(api::errors::MISSING_API_KEY);
    let mut config = config::Config::new();
    config.load_config();

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
            api::acc_breach_request(&line, &config.api_key);
            // Only one request every 1500 milliseconds from any given IP
            thread::sleep(time::Duration::from_millis(1600));
        }
    } else {
        api::acc_breach_request(data_search, &config.api_key);
    }
}

fn pass_check(data_search: &api::PassArg) {
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::USER_AGENT,
        header::HeaderValue::from_static(api::CHECKPWN_USER_AGENT),
    );
    headers.insert(
        "Add-Padding",
        header::HeaderValue::from_str("true").unwrap(),
    );

    let client = Client::builder().default_headers(headers).build().unwrap();

    let mut hashed_password = api::hash_password(&data_search.password);
    let uri_acc = api::arg_to_api_route(&api::CheckableChoices::PASS, &hashed_password);

    set_checkpwn_panic!(api::errors::NETWORK_ERROR);
    let pass_stat = client.get(&uri_acc).send().unwrap();

    set_checkpwn_panic!(api::errors::DECODING_ERROR);
    let request_status = pass_stat.status();
    let pass_body: String = pass_stat.text().unwrap();

    if api::search_in_range(&pass_body, &hashed_password) {
        api::breach_report(request_status, "", true);
    } else {
        api::breach_report(StatusCode::NOT_FOUND, "", true);
    }

    // Zero out as this contains a weakly hashed password
    hashed_password.zeroize();
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
        "register" => {
            assert!(argvs.len() == 3);
            let configuration = config::Config::new();
            let config_path = configuration
                .get_config_path()
                .expect("Failed to determine configuration file path.");

            if !config_path.config_file_path.exists() {
                match configuration.save_config(&argvs[2]) {
                    Ok(()) => println!("Successfully saved client configuration."),
                    Err(e) => panic!("Encountered error saving client configuration: {}", e),
                }
            } else {
                println!(
                    "A configuration file already exists. Do you want to overwrite it? [y/n]: "
                );
                let mut overwrite_choice = String::new();

                stdin().read_line(&mut overwrite_choice).unwrap();
                overwrite_choice.to_lowercase();

                match overwrite_choice.trim() {
                    "y" => match configuration.save_config(&argvs[2]) {
                        Ok(()) => println!("Successfully saved new client configuration."),
                        Err(e) => panic!("Encountered error saving client configuration: {}", e),
                    },
                    "n" => println!("Configuration unchanged. Exiting client."),
                    _ => panic!("Invalid choice. Please enter 'y' for 'yes' or 'n' for 'no'."),
                }
            }
        }
        _ => panic!(),
    };
    // Zero out the collected arguments, in case the user accidentally inputs sensitive info
    for argument in argvs.iter_mut() {
        argument.zeroize();
    }
    // Only one request every 1500 milliseconds from any given IP
    thread::sleep(time::Duration::from_millis(1600));
}

#[test]
fn test_cli_acc_breach() {
    let res = Command::new("cargo")
        .args(&["run", "acc", "test@example.com"])
        .unwrap();

    assert!(String::from_utf8_lossy(&res.stdout).contains("BREACH FOUND"));
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
