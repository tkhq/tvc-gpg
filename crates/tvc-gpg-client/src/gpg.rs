//! The two gpg calls: one to sign the request, one to read the message.

use crate::Result;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufRead as _, BufReader, Write as _, stderr};
use std::path::Path;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

/// What gpg calls the session key in its own diagnostics.
const SESSION_KEY_MARKER: &str = "seskey";

/// The argv for a detached signature over the request payload.
///
/// `--no-armor` is here because the app wants one raw signature packet, and a
/// user with `armor` in `gpg.conf` would otherwise send armor text.
#[must_use]
pub fn sign_args(signer: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "--batch".to_owned(),
        "--no-armor".to_owned(),
        "--detach-sign".to_owned(),
        "--output".to_owned(),
        "-".to_owned(),
    ];
    if let Some(signer) = signer {
        args.push("--local-user".to_owned());
        args.push(signer.to_owned());
    }
    args
}

/// The argv for a session key decrypt of the file at `path`.
///
/// The session key goes in on stdin, so it never lands in a file or in the
/// process table. `--logger-fd 2` sends every gpg diagnostic down one pipe
/// this client can filter, because gpg prints the session key there. `--`
/// stops gpg reading a file name such as `-oops.gpg` as an option. The path
/// keeps its own bytes, so a name that is not UTF-8 still reaches gpg
/// unchanged.
#[must_use]
pub fn decrypt_args(path: &Path) -> Vec<OsString> {
    vec![
        OsString::from("--batch"),
        OsString::from("--logger-fd"),
        OsString::from("2"),
        OsString::from("--override-session-key-fd"),
        OsString::from("0"),
        OsString::from("--decrypt"),
        OsString::from("--"),
        path.as_os_str().to_owned(),
    ]
}

/// Whether a gpg diagnostic line carries the session key.
///
/// gpg prints `gpg: DBG: seskey: <algorithm>:<hex>` on every run that
/// overrides the session key, and no gpg option turns that off.
#[must_use]
pub fn leaks_session_key(line: &str) -> bool {
    line.contains(SESSION_KEY_MARKER)
}

/// Sign `payload` with gpg and return the raw signature packet.
///
/// gpg-agent asks for the YubiKey tap here.
///
/// # Errors
///
/// Returns an error if gpg cannot run or does not sign.
pub fn sign(payload: &[u8], signer: Option<&str>) -> Result<Vec<u8>> {
    let mut child = Command::new("gpg")
        .args(sign_args(signer))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("gpg could not be started: {error}"))?;
    // A gpg that exits before it reads stdin, say because it has no secret key
    // for the signer, breaks the pipe. Its own exit status says more than the
    // write error does, so always wait and report that first.
    let written = child
        .stdin
        .take()
        .ok_or("gpg did not take the payload")?
        .write_all(payload);
    let output = child
        .wait_with_output()
        .map_err(|error| format!("gpg did not finish: {error}"))?;
    if !output.status.success() {
        return Err(format!("gpg did not sign the request, it exited {}", output.status).into());
    }
    written.map_err(|error| format!("gpg did not take the payload: {error}"))?;
    Ok(output.stdout)
}

/// gpg's `<algorithm>:<upper case hex>` form of a session key.
///
/// The text is built straight into the wiped buffer, so no unwiped copy of
/// the key is ever allocated.
///
/// # Errors
///
/// Returns an error if the plaintext is too short to hold a key.
pub fn session_key_string(plain: &[u8]) -> Result<Zeroizing<String>> {
    let (algorithm, key) = plain.split_first().ok_or("the session key is empty")?;
    let mut text = Zeroizing::new(String::with_capacity(4 + key.len() * 2));
    write!(text, "{algorithm}:").map_err(|error| format!("the session key: {error}"))?;
    for byte in key {
        write!(text, "{byte:02X}").map_err(|error| format!("the session key: {error}"))?;
    }
    Ok(text)
}

/// Read the message at `path` with `session_key` and return gpg's exit code.
///
/// The plaintext goes straight from gpg to `output` or to this process's
/// stdout, so it never passes through the client. gpg's diagnostics come back
/// on a pipe that a reader thread forwards to this process's stderr, minus
/// the line that carries the session key. The thread is what keeps that pipe
/// from filling while gpg runs.
///
/// # Errors
///
/// Returns an error if gpg cannot run or the output file cannot be opened.
pub fn decrypt(session_key: &str, path: &Path, output: Option<&Path>) -> Result<i32> {
    let stdout = match output {
        Some(output) => Stdio::from(
            File::create(output)
                .map_err(|error| format!("the output file could not be opened: {error}"))?,
        ),
        None => Stdio::inherit(),
    };
    let mut child = Command::new("gpg")
        .args(decrypt_args(path))
        .stdin(Stdio::piped())
        .stdout(stdout)
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("gpg could not be started: {error}"))?;

    let diagnostics = child.stderr.take().ok_or("gpg kept its diagnostics")?;
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(diagnostics)
            .lines()
            .map_while(std::result::Result::ok)
        {
            if !leaks_session_key(&line) {
                let _ = writeln!(stderr(), "{line}");
            }
        }
    });

    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or("gpg did not take the session key")?;
        writeln!(stdin, "{session_key}")
            .map_err(|error| format!("gpg did not take the session key: {error}"))?;
    }
    let status = child
        .wait()
        .map_err(|error| format!("gpg did not finish: {error}"))?;
    let _ = reader.join();
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Read as _;

    /// A message a real gpg made and the session key it reported, from the
    /// server crate's interop fixtures.
    const GPG_MESSAGE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tvc-gpg/fixtures/message.gpg"
    );
    const GPG_SESSION_KEY: &str = include_str!("../../tvc-gpg/fixtures/session-key.txt");

    #[test]
    fn the_sign_argv_asks_for_one_raw_signature_packet() {
        assert_eq!(
            sign_args(None),
            ["--batch", "--no-armor", "--detach-sign", "--output", "-"]
        );
        assert_eq!(
            sign_args(Some("akshar@turnkey.io")),
            [
                "--batch",
                "--no-armor",
                "--detach-sign",
                "--output",
                "-",
                "--local-user",
                "akshar@turnkey.io",
            ]
        );
    }

    #[test]
    fn the_decrypt_argv_reads_the_session_key_from_stdin() {
        assert_eq!(
            decrypt_args(Path::new("-oops.gpg")),
            [
                "--batch",
                "--logger-fd",
                "2",
                "--override-session-key-fd",
                "0",
                "--decrypt",
                "--",
                "-oops.gpg",
            ]
        );
    }

    #[test]
    fn only_the_session_key_line_is_dropped() {
        assert!(leaks_session_key(
            "gpg: DBG: seskey: 9:015FC1D5FCF8EEA9495945EF6E325ECFACC42B1C7BCE899CAEE7B9FC77CB3596"
        ));
        for line in [
            "gpg: encrypted with 256-bit ECDH key",
            "gpg: WARNING: message was not integrity protected",
            "gpg: decryption failed: No secret key",
            "",
        ] {
            assert!(!leaks_session_key(line), "{line} was dropped");
        }
    }

    #[test]
    fn the_session_key_string_is_the_form_gpg_reads() {
        assert_eq!(
            session_key_string(&[9, 0xab, 0xcd]).unwrap().as_str(),
            "9:ABCD"
        );
        assert!(session_key_string(&[]).is_err());
    }

    #[test]
    fn gpg_reads_a_fixture_message_with_its_session_key() {
        let output = tempfile::NamedTempFile::new().unwrap();

        let code = decrypt(
            GPG_SESSION_KEY.trim(),
            Path::new(GPG_MESSAGE),
            Some(output.path()),
        )
        .unwrap();

        assert_eq!(code, 0, "gpg did not read the message");
        let mut plaintext = String::new();
        output.as_file().read_to_string(&mut plaintext).unwrap();
        assert_eq!(plaintext, "hello team\n");
    }
}
