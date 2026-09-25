//! Client for the TVC GPG app.
//!
//! The app holds the team OpenPGP key. It never sees the message: the client
//! sends it only the session key packet addressed to the team subkey, signed
//! with the caller's own GPG key, and gets the session key back wrapped to a
//! one time transport key. gpg then reads the message with that session key.

pub mod gpg;
pub mod message;
pub mod request;

use clap::{Args, Parser, Subcommand};
use qos_p256::encrypt::P256EncryptPair;
use std::io::{Read as _, Write as _, stdin};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

/// Anything that stops a run, in words a caller can act on.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Client for the TVC GPG app.
#[derive(Parser, Debug)]
#[command(name = "tvc-gpg-client", version)]
pub struct Cli {
    /// Which subcommand to run
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands the client offers.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Decrypt a message encrypted to the team key
    Decrypt(Decrypt),
}

/// Arguments for `decrypt`.
#[derive(Args, Debug)]
pub struct Decrypt {
    /// Base URL of the deployed app
    #[arg(long)]
    pub app_url: String,

    /// App id the deployment runs under
    #[arg(long)]
    pub app_id: String,

    /// Hex of the app's quorum public key, 130 bytes
    #[arg(long)]
    pub quorum_public_key: String,

    /// GPG user id or fingerprint to sign the request with
    #[arg(long)]
    pub signer: Option<String>,

    /// Write the plaintext here instead of stdout
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// The message to read, binary or armored. "-" reads stdin
    pub file: PathBuf,
}

/// Run one command and return the exit code to leave with.
///
/// # Errors
///
/// Returns an error if any step fails. gpg's own exit code comes back as the
/// return value, not as an error.
pub fn run(cli: &Cli) -> Result<i32> {
    let Command::Decrypt(args) = &cli.command;
    decrypt(args)
}

/// Fetch a session key from the app and hand it to gpg.
fn decrypt(args: &Decrypt) -> Result<i32> {
    // The pinned key is local input, so read it before anything leaves this
    // machine. A typo in it must not cost a tap and an audit record.
    let quorum = request::pinned_quorum_key(&args.quorum_public_key)?;

    let message = read_message(&args.file)?;
    let packets = message::packet_bytes(&message)?;
    let pkesks = message::session_key_packets(&packets)?;

    let app_key = request::fetch_public_key(&args.app_url)?;
    let subkey_id = message::encryption_subkey_id(&app_key)?;
    let pkesk = message::pkesk_for(&pkesks, &subkey_id)?;

    let transport = P256EncryptPair::generate();
    let transport_public_key = qos_hex::encode(&transport.public_key().to_bytes());

    // The app allows 300 seconds either side of its own clock, and the tap on
    // the YubiKey happens inside the signing call, so read the clock last.
    let payload = request::payload_json(
        &args.app_id,
        &qos_hex::encode(&pkesk),
        &transport_public_key,
        now()?,
    )?;
    let signature = gpg::sign(payload.as_bytes(), args.signer.as_deref())?;

    let response = request::post_session_key(&args.app_url, &payload, &signature)?;
    request::check_response(
        &response,
        &quorum,
        &args.app_id,
        &transport_public_key,
        &pkesk,
    )?;
    let plain = request::open_session_key(&transport, &response.wrapped_session_key)?;
    let session_key = gpg::session_key_string(&plain)?;

    // gpg reads the session key from stdin, so the message has to be a file.
    let temporary = if is_stdin(&args.file) {
        Some(spill(&message)?)
    } else {
        None
    };
    let path = temporary
        .as_ref()
        .map_or(args.file.as_path(), NamedTempFile::path);
    gpg::decrypt(&session_key, path, args.output.as_deref())
}

/// Whether `file` asks for stdin.
fn is_stdin(file: &Path) -> bool {
    file.as_os_str() == "-"
}

/// Read the message from a file, or from stdin when `file` is "-".
fn read_message(file: &Path) -> Result<Vec<u8>> {
    if is_stdin(file) {
        let mut message = Vec::new();
        stdin()
            .read_to_end(&mut message)
            .map_err(|error| format!("stdin could not be read: {error}"))?;
        return Ok(message);
    }
    std::fs::read(file)
        .map_err(|error| format!("{} could not be read: {error}", file.display()).into())
}

/// Write a message read from stdin to a temporary file for gpg.
fn spill(message: &[u8]) -> Result<NamedTempFile> {
    let mut file = NamedTempFile::new().map_err(|error| format!("no temporary file: {error}"))?;
    file.write_all(message)
        .map_err(|error| format!("the temporary file could not be written: {error}"))?;
    Ok(file)
}

/// The caller's clock, in seconds since the epoch.
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .map_err(|_| "this machine's clock is before the epoch".into())
}
