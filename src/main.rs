// MIT License

// Copyright (c) 2018-2021 brycx

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

#![forbid(unsafe_code)]
#![deny(clippy::mem_forget)]
#![warn(
    rust_2018_idioms,
    trivial_casts,
    unused_qualifications,
    overflowing_literals
)]

mod config;
#[macro_use]
mod errors;

use anyhow::Result;
use checkpwn_lib::Password;
use colored::Colorize;

use std::fs::File;
use std::io::{BufReader, Error};

#[cfg(test)]
use assert_cmd::prelude::*;
use std::env;
use std::io::{stdin, BufRead};
use std::panic;
#[cfg(test)]
use std::process::Command;
use zeroize::Zeroize;

fn main() -> Result<()> {
    // Set custom usage panic message
    set_checkpwn_panic!(errors::USAGE_ERROR);
    assert!(env::args().len() >= 2);
    assert!(env::args().len() < 4);

    let mut argvs: Vec<String> = env::args().collect();

    match argvs[1].to_lowercase().as_str() {
        "acc" => {
            assert!(argvs.len() == 3);
            acc_check(&argvs[2])?;
        }
        "pass" => {
            assert!(argvs.len() == 2);
            let hashed_password = Password::new(&rpassword::prompt_password_stdout("Password: ")?)?;
            let is_breached = checkpwn_lib::check_password(&hashed_password)?;
            breach_report(is_breached, "", true);
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

                stdin().read_line(&mut overwrite_choice)?;
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
    argvs.iter_mut().zeroize();

    Ok(())
}

/// Make a breach report based on a u16 status code and print result to terminal.
fn breach_report(breached: bool, searchterm: &str, is_password: bool) {
    // Do not display password in terminal
    let request_key = if is_password { "********" } else { searchterm };

    if breached {
        println!(
            "Breach status for {}: {}",
            request_key.cyan(),
            "BREACH FOUND".red()
        );
    } else {
        println!(
            "Breach status for {}: {}",
            request_key.cyan(),
            "NO BREACH FOUND".green()
        );
    }
}

/// Read file into buffer.
fn read_file(path: &str) -> Result<BufReader<File>, Error> {
    set_checkpwn_panic!(errors::READ_FILE_ERROR);
    let file_path = File::open(path).unwrap();

    Ok(BufReader::new(file_path))
}

/// Strip all whitespace and all newlines from a given string.
fn strip(string: &str) -> String {
    string
        .replace("\n", "")
        .replace(" ", "")
        .replace("\'", "'")
        .replace("\t", "")
}

/// HIBP breach request used for `acc` arguments.
fn acc_breach_request(searchterm: &str, api_key: &str) -> Result<(), checkpwn_lib::CheckpwnError> {
    let is_breached = checkpwn_lib::check_account(searchterm, api_key)?;
    breach_report(is_breached, searchterm, false);

    Ok(())
}

fn acc_check(data_search: &str) -> Result<(), checkpwn_lib::CheckpwnError> {
    // NOTE: checkpwn_lib handles any sleeping so we don't exceed the rate limit.
    set_checkpwn_panic!(errors::MISSING_API_KEY);
    let mut config = config::Config::new();
    config.load_config().unwrap();

    // Check if user wants to check a local list
    if data_search.ends_with(".ls") {
        set_checkpwn_panic!(errors::BUFREADER_ERROR);
        let file = read_file(data_search).unwrap();

        for line_iter in file.lines() {
            set_checkpwn_panic!(errors::READLINE_ERROR);
            let line = strip(&line_iter.unwrap());
            if line.is_empty() {
                continue;
            }
            acc_breach_request(&line, &config.api_key)?;
        }
    } else {
        acc_breach_request(data_search, &config.api_key)?;
    }

    Ok(())
}

#[test]
fn test_strip_white_new() {
    let string_1 = String::from("fkljjsdjlksfdklj dfiwj wefwefwfe");
    let string_2 = String::from("derbrererer\n");
    let string_3 = String::from("dee\nwfweww   rb  tte rererer\n");

    assert_eq!(&strip(&string_1), "fkljjsdjlksfdkljdfiwjwefwefwfe");
    assert_eq!(&strip(&string_2), "derbrererer");
    assert_eq!(&strip(&string_3), "deewfwewwrbtterererer");
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
