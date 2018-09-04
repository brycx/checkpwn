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
use reqwest::header::UserAgent;
use reqwest::StatusCode;
use std::io::BufRead;
use std::panic::{self, PanicInfo};
#[cfg(test)]
use std::process::Command;
use std::{env, thread, time};

fn main() {
    let argvs: Vec<String> = env::args().collect();
    // Set custom usage panic message
    setup_checkpwn_panic!(api::errors::USAGE_ERROR);

    if argvs.len() >= 2 {
        ()
    } else {
        panic!();
    }

    let option_arg = argvs[1].to_lowercase();

    let mut data_search = String::new();

    match &option_arg as &str {
        api::ACCOUNT => {
            if argvs.len() != 3 {
                panic!();
            }
            data_search = argvs[2].to_owned();
        }
        api::PASSWORD => {
            if argvs.len() != 2 {
                panic!();
            }
            api::errors::panic_set_reset_hook(api::errors::PASSWORD_ERROR);
            data_search = rpassword::prompt_password_stdout("Password: ").unwrap();
        }
        _ => panic!(),
    };

    if option_arg == api::ACCOUNT {
        // Check if user wants to check a local list
        if data_search.to_owned().ends_with(".ls") {
            api::errors::panic_set_reset_hook(api::errors::BUFREADER_ERROR);
            let file = api::read_file(&data_search).unwrap();

            for line_iter in file.lines() {
                api::errors::panic_set_reset_hook(api::errors::READLINE_ERROR);
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
        api::errors::panic_set_reset_hook(api::errors::NETWORK_ERROR);
        let mut pass_stat = client
            .get(&uri_acc)
            .header(UserAgent::new(api::USER_AGENT))
            .send()
            .unwrap();

        api::errors::panic_set_reset_hook(api::errors::DECODING_ERROR);
        let pass_body: String = pass_stat.text().unwrap();
        let breach_bool = api::search_in_range(api::split_range(&pass_body), &hashed_password);

        if breach_bool {
            api::breach_report(pass_stat.status(), &data_search, true);
        } else {
            api::breach_report(StatusCode::NotFound, &data_search, true);
        }

        // Zero out as this contains a weakly hashed password
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
