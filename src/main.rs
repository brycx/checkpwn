extern crate futures;
extern crate hyper;
extern crate hyper_tls;
extern crate tokio_core;
#[cfg(test)]
extern crate assert_cli;

pub mod api;

use std::{thread, time, env};
use std::io::BufRead;

use futures::{Future, Stream};
use tokio_core::reactor::Core;
use hyper::{Client, StatusCode, Chunk};
use hyper_tls::HttpsConnector;

fn main() {

    let mut core = Core::new().expect("Failed to initialize Tokio core");
    let client = Client::configure()
        .connector(HttpsConnector::new(4, &core.handle()).expect("Failed to set HTTPS as hyper connector"))
        .build(&core.handle());

    let argvs: Vec<String> = env::args().collect();
    if argvs.len() != 3 {
        panic!("Usage: checkpwn acc test@example.com");
    }

    let option_arg = &argvs[1].to_lowercase();
    let data_search = &argvs[2];

    if data_search.to_owned().ends_with(".ls") {
        
        let file = api::util::read_file(data_search).unwrap();

        for line_iter in file.lines() {
            let line = line_iter.unwrap();

            let (requester_acc, requester_paste) = api::breach_request(&line, option_arg);

            let get_acc = client.request(requester_acc).map(|res| {
                res.status()
            });

            let get_paste = client.request(requester_paste).map(|res| {
                res.status()
            });
        
            let work = get_acc.join(get_paste);
            let (acc_stat, paste_stat) = core.run(work).expect("Failed to run Tokio core");
            // Return breach report
            api::evaluate_breach(acc_stat, paste_stat, line);

            // Only one request every 1500 miliseconds from any given IP
            thread::sleep(time::Duration::from_millis(1600));       
        }
    }

    else {        

        let (requester_acc, requester_paste) = api::breach_request(data_search, option_arg);
        
        if option_arg.to_owned() == api::ACCOUNT {        

            let get_acc = client.request(requester_acc).map(|res| {
                res.status()
            });

            let get_paste = client.request(requester_paste).map(|res| {
                res.status()
            });

            let work = get_acc.join(get_paste);
            let (acc_stat, paste_stat) = core.run(work).expect("Failed to run Tokio core");
            // Return breach report
            api::evaluate_breach(acc_stat, paste_stat, data_search.to_owned());
        
        } else if option_arg.to_owned() == api::PASSWORD {
            
            let work = client.request(requester_acc).and_then(|res| {

                let status_code = res.status();
                
                res.body().concat2().and_then(move |body: Chunk| {                    
                    
                    if option_arg.to_owned() == api::PASSWORD {
                    
                        let breach_bool = api::search_in_range(api::split_range(&body.to_vec()), data_search.to_owned());
                        
                        if breach_bool == true {
                            api::breach_report(status_code, data_search.to_owned());
                        } else { api::breach_report(StatusCode::NotFound, data_search.to_owned()); }
                    }   
                    
                    Ok(())                
                })
            });

            core.run(work).expect("Failed to run Tokio core");
        }
    }
}



#[test]
fn test_cli_acc() {

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