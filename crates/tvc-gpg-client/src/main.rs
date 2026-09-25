//! Entry point for the TVC GPG client.

use clap::Parser as _;
use tvc_gpg_client::{Cli, run};

fn main() {
    // `run` owns the temporary file that holds a message read from stdin, so
    // let it return before this process exits. `exit` skips destructors.
    let code = match run(&Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("tvc-gpg-client: {error}");
            1
        }
    };
    std::process::exit(code);
}
