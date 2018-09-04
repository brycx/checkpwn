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

use std::panic::{self, PanicInfo};

/// All the different errors for checkpwn;
/// Errors that are meant to be internal or or unreachable print this.
pub const USAGE_ERROR: &str = "Usage: checkpwn (acc/pass) (username/email/account_list.ls)";
pub const STATUSCODE_ERROR: &str = "Unrecognized status code recevied";
pub const PASSWORD_ERROR: &str = "Error retrieving password from stdin";
pub const READ_FILE_ERROR: &str = "Error reading local file";
pub const NETWORK_ERROR: &str = "Failed to send request to HIBP";
pub const DECODING_ERROR: &str = "Failed to decode response from HIBP";
pub const API_ARG_ERROR: &str = "SHOULD_BE_UNREACHABLE: Invalid argument in API route construction detected";
pub const BAD_RESPONSE_ERROR: &str = "Recevied a bad response from HIBP - make sure the account is valid";
pub const BUFREADER_ERROR: &str = "Failed to read file in to BufReader";
pub const READLINE_ERROR: &str = "Failed to read line from file";


macro_rules! setup_checkpwn_panic {
    ($x:expr) => {
        panic::set_hook(Box::new(move |_info: &PanicInfo| {
            println!("\nThe following error was encountered: {:?}\n\
            \nIf you think this is a bug, please report it.",
            $x);
        }));
    };
}
/// Used to reset the panic hook with a new panic message.
pub fn panic_set_reset_hook(error_msg: &'static str) {
    // Unregister current panic hook
    panic::take_hook();
    // Sets the new panic hook with a custom panic message
    setup_checkpwn_panic!(error_msg);
}
