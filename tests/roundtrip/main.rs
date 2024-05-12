mod expected;

use std::path::{Path, PathBuf};

use rstest::rstest;
use ssh_agent_lib::proto::{Request, Response};
use ssh_encoding::{Decode, Encode};
use testresult::TestResult;

fn roundtrip<T>(path: impl AsRef<Path>, expected: Option<T>) -> TestResult
where
    T: Decode + Encode + PartialEq + std::fmt::Debug,
    T::Error: std::fmt::Display,
{
    let serialized = std::fs::read(path)?;
    let mut bytes: &[u8] = &serialized;
    let message = T::decode(&mut bytes)?;
    eprintln!("Message: {message:#?}");
    if let Some(expected) = expected {
        eprintln!("Expected: {expected:#?}");
        assert_eq!(
            expected, message,
            "parsed message does not match expected object"
        );
    }
    let mut out = vec![];
    message.encode(&mut out)?;
    assert_eq!(
        serialized, out,
        "roundtripped message should be exactly identical to saved sample"
    );
    assert_eq!(
        out.len(),
        message.encoded_len()?,
        "the encoded message length should be equal to saved sample"
    );
    Ok(())
}

#[rstest]
fn roundtrip_requests(#[files("tests/messages/req-*.bin")] path: PathBuf) -> TestResult {
    roundtrip::<Request>(&path, expected::request(&path))
}

#[rstest]
fn roundtrip_responses(#[files("tests/messages/resp-*.bin")] path: PathBuf) -> TestResult {
    roundtrip::<Response>(&path, expected::response(&path))
}
