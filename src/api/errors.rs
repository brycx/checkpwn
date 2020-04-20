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

/// All the different errors for checkpwn;
/// Errors that are meant to be internal or or unreachable print this.
pub const USAGE_ERROR: &str =
    "Usage: checkpwn { pass | acc (<username> | <email> | <filename>.ls) | register <apikey> }";
pub const STATUSCODE_ERROR: &str = "Unrecognized status code received";
pub const PASSWORD_ERROR: &str = "Error retrieving password from stdin";
pub const READ_FILE_ERROR: &str = "Error reading local file";
pub const NETWORK_ERROR: &str = "Failed to send request to HIBP";
pub const DECODING_ERROR: &str = "Failed to decode response from HIBP";
pub const API_ARG_ERROR: &str =
    "SHOULD_BE_UNREACHABLE: Invalid argument in API route construction detected";
pub const BAD_RESPONSE_ERROR: &str =
    "Received a bad response from HIBP - make sure the account is valid";
pub const BUFREADER_ERROR: &str = "Failed to read file in to BufReader";
pub const READLINE_ERROR: &str = "Failed to read line from file";
pub const INVALID_API_KEY: &str = "HIBP deemed the current API key invalid";
pub const MISSING_API_KEY: &str = "Failed to read or parse the configuration file 'checkpwn.yml'. You need to register an API key to be able to check accounts";

/// Set panic hook, to have .unwrap(), etc, return the custom panic message.
macro_rules! set_checkpwn_panic {
    ($x:expr) => {
        // Set new hook with custom message
        panic::set_hook(Box::new(|_| {
            println!(
                "\nThe following error was encountered: {:?}\n\
                 \nIf you think this is a bug, please report it in the project repository.",
                $x
            );
        }));
    };
}
