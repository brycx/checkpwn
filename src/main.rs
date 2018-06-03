#[cfg(test)]
extern crate assert_cli;
extern crate reqwest;
pub mod api;

use std::{thread, time, env};
use std::io::BufRead;
use reqwest::header::UserAgent;
use reqwest::StatusCode;

fn main() {

    let argvs: Vec<String> = env::args().collect();
    if argvs.len() != 3 {
        panic!("Usage: checkpwn acc test@example.com");
    }

    let option_arg = argvs[1].to_lowercase();
    
    match &option_arg as &str {
        api::ACCOUNT => (),
        api::PASSWORD => (),
        _ => panic!("Usage: checkpwn acc test@example.com")
    };

    let data_search = argvs[2].to_owned();

    if data_search.to_owned().ends_with(".ls") {
        
        let file = api::read_file(&data_search).unwrap();

        for line_iter in file.lines() {

            let line = line_iter.unwrap();

            api::breach_request(&line, &option_arg);
            // Only one request every 1500 miliseconds from any given IP
            thread::sleep(time::Duration::from_millis(1600));
        }
    }

    else {

        if option_arg.to_owned() == api::ACCOUNT {

            api::breach_request(&data_search, &option_arg);
            // Only one request every 1500 miliseconds from any given IP
            thread::sleep(time::Duration::from_millis(1600));
        
        } else if option_arg.to_owned() == api::PASSWORD {

            let client = reqwest::Client::new();
            let uri_acc = api::arg_to_api_route(option_arg.to_owned(), data_search.to_owned());
            let mut pass_stat = client.get(&uri_acc)
                .header(UserAgent::new("checkpwn - cargo utility tool for hibp"))
                .send().unwrap();

            let status_code = pass_stat.status();
            let pass_body = pass_stat.text().unwrap();
            let breach_bool = api::search_in_range(api::split_range(&pass_body.as_bytes().to_vec()), data_search.to_owned());        
            
            match breach_bool {
                true => { api::breach_report(status_code, data_search.to_owned()); },
                false => { api::breach_report(StatusCode::NotFound, data_search.to_owned()); }
            }
        }
    }
}



#[test]
fn test_cli_acc() {
    // Wait, so that test don't get blocked
    thread::sleep(time::Duration::from_millis(1600));       

    assert_cli::Assert::command(&["cargo", "run", "acc", "test@example.com"])
        .stdout().contains("BREACH FOUND")
        .unwrap();
}

#[test]
#[should_panic]
// Doing the reverse, since I'm unsure how the coloreed module affects this
fn test_cli_acc_fail() {

    assert_cli::Assert::command(&["cargo", "run", "acc", "test@example.com"])
        .stdout().contains("NO BREACH FOUND")
        .unwrap();
}

#[test]
#[should_panic]
fn test_cli_arg_fail() {

    assert_cli::Assert::command(&["cargo", "run", "wrong", "test@example.com"])
        .stdout().contains("NO BREACH FOUND")
        .unwrap();
}