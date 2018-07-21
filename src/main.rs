#[cfg(test)]
extern crate assert_cli;
extern crate reqwest;
extern crate rpassword;
pub mod api;

use reqwest::header::UserAgent;
use reqwest::StatusCode;
use std::io::BufRead;
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
                api::split_range(&pass_body.as_bytes().to_vec()), &data_search,
            );

            if breach_bool {
                api::breach_report(status_code, &data_search);
            } else {
                api::breach_report(StatusCode::NotFound, &data_search);
            }
    }
}

#[test]
fn test_cli_acc() {
    // Wait, so that test don't get blocked
    thread::sleep(time::Duration::from_millis(1600));

    assert_cli::Assert::command(&["cargo", "run", "acc", "test@example.com"])
        .stdout()
        .contains("BREACH FOUND")
        .unwrap();
}

#[test]
#[should_panic]
// Doing the reverse, since I'm unsure how the coloreed module affects this
fn test_cli_acc_fail() {
    assert_cli::Assert::command(&["cargo", "run", "acc", "test@example.com"])
        .stdout()
        .contains("NO BREACH FOUND")
        .unwrap();
}

#[test]
#[should_panic]
fn test_cli_arg_fail() {
    assert_cli::Assert::command(&["cargo", "run", "wrong", "test@example.com"])
        .stdout()
        .contains("NO BREACH FOUND")
        .unwrap();
}
